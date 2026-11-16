"""Frozen original policy, independent HIA VM and actual native decisions."""
from __future__ import annotations

import ast
import builtins
import copy
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import random
import shutil
from statistics import median
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import hia_multiversion as owner
from hepta.hia_publication_measurement_native import (NativePublicationMeasurement,
    OUTPUT_BYTES, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE, STATE_BYTES,
    installed_publication_measurement, packet)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/publication_measurement_698cc280.py.txt'
FIXTURE_SHA256 = 'e705071aba79546ed70c984fd57fbe15b9394909a55382237fad8aa6308f07d1'


def original_policy():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise AssertionError('frozen original publication policy changed')
    scope = {'median': median, 'json': json, 'sha256': sha256,
             '_DECISION_RESERVE_NS': 2_000_000_000,
             'MEASUREMENT_POLICY': 'paired-native-artifact-cost-v1', '_reject': owner._reject}
    exec(compile(raw, str(FIXTURE), 'exec'), scope)
    return scope['_assess_measurement']


def measurement(*, samples=15, baseline=1_000_000, candidate=500_000, **values):
    value = {'schema': owner.MEASUREMENT_SCHEMA, 'before_sha256': '0' * 64,
        'after_sha256': '1' * 64, 'before_artifact_sha256': 'a' * 64,
        'after_artifact_sha256': 'b' * 64, 'workload_sha256': 'c' * 64,
        'function': 'transition', 'calls_per_sample': 1, 'horizon_calls': 1_000_000,
        'search_cost_ns': 0, 'maximum_search_ns': 3_600_000_000_000,
        'samples': [{'baseline_ns': baseline, 'candidate_ns': candidate} for _ in range(samples)]}
    value.update(values)
    return owner._measurement_snapshot(value)


def outcome(function, value, prepare):
    try:
        return ('returned', function(value, prepare_ns=prepare))
    except Exception as error:
        cause = None if error.__cause__ is None else (type(error.__cause__).__name__, str(error.__cause__))
        return ('raised', type(error).__name__, str(error), cause)


class VM:
    def __init__(self):
        from hepta.hia_agent_assembly import assemble_program
        self.checked = assemble_program(SOURCE.read_bytes())
        self.entry = next(f for f in self.checked.as_dict()['functions'] if f['name'] == 'f0')

    def call(self, raw, output_size=OUTPUT_BYTES, state_size=STATE_BYTES):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'\xa5' * output_size)),
                  _Owner(-3, bytearray(state_size))]
        machine = _Machine(self.checked, 50_000_000, 16 << 20, None, 128)
        code = machine.invoke(self.entry,
            [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
        return code, bytes(owners[1].data), bytes(owners[2].data)


def native_call(image, raw, output_size=OUTPUT_BYTES, state_size=STATE_BYTES):
    source = ctypes.create_string_buffer(raw, max(1, len(raw)))
    output = ctypes.create_string_buffer(b'\xa5' * (output_size + 16), output_size + 16)
    state = ctypes.create_string_buffer(state_size + 16)
    ctypes.memset(ctypes.addressof(state) + state_size, 0x91, 16)
    result = image._entry(source, len(raw), output, output_size, state, state_size)
    if (source.raw != (raw or b'\0') or output.raw[output_size:] != b'\xa5' * 16
            or state.raw[state_size:] != b'\x91' * 16):
        raise AssertionError('native publication measurement changed transport/canary bytes')
    return result, output.raw[:output_size], state.raw[:state_size]


class PublicationMeasurementSourceTests(unittest.TestCase):
    def test_generated_source_and_frozen_original_function_identity(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_publication_measurement import document
        self.assertEqual(render_assembly(document()), SOURCE.read_text())
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(outcome(original_policy(), measurement(), 17),
                         outcome(owner._reference_assess_measurement, measurement(), 17))
        tree = ast.parse((ROOT / 'hepta/hia_multiversion.py').read_text())
        original = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == '_reference_assess_measurement')
        original.name = '_assess_measurement'
        self.assertEqual(ast.dump(original, include_attributes=False),
                         ast.dump(ast.parse(FIXTURE.read_text()).body[0], include_attributes=False))

    def test_independent_vm_decides_actual_nontrivial_policy_and_full_projection(self):
        vm = VM()
        cases = [(measurement(), 17),
                 (measurement(baseline=60_000_000_000, candidate=30_000_000_000,
                              horizon_calls=1_000_000_000_000, calls_per_sample=64_000_000), 123),
                 (measurement(baseline=1, candidate=60_000_000_000, horizon_calls=1_000_000_000_000),
                  -(60_000_000_000_000_000_000_000 + 2_000_000_000) + 1),
                 (measurement(baseline=1, candidate=2), 1 << 300)]
        for value, prepare in cases:
            with self.subTest(prepare=prepare, count=value['calls_per_sample']):
                code, output, _state = vm.call(packet(value, prepare))
                self.assertEqual(code, OUTPUT_BYTES)
                words = struct.unpack('<22Q', output)
                self.assertEqual(words[0], RESULT_MAGIC)
                expected = outcome(original_policy(), value, prepare)
                if expected[0] == 'raised':
                    self.assertEqual(words[1], 1)
                else:
                    self.assertEqual(words[1], 0)
                    result = expected[1]
                    self.assertEqual(words[16:18], (result['projected_baseline_total_ns'],
                                                  result['projected_candidate_total_ns']))
                    self.assertEqual(bool(words[21]), result['eligible'])

    def test_default_path_does_not_import_optional_native_adapter(self):
        original_import = builtins.__import__
        def blocked(name, *args, **kwargs):
            if 'publication_measurement_native' in name:
                raise AssertionError('default path imported optional native adapter')
            return original_import(name, *args, **kwargs)
        clean = {key: value for key, value in os.environ.items() if key != SELECTOR}
        with patch.dict(os.environ, clean, clear=True), patch('builtins.__import__', blocked):
            self.assertEqual(owner._assess_measurement(measurement(), prepare_ns=23),
                             original_policy()(measurement(), prepare_ns=23))


class PublicationMeasurementNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get('HEPTA_HIA_PUBLICATION_MEASUREMENT_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_PUBLICATION_MEASUREMENT_DEVELOPMENT_COMPILER')
        if cold and development:
            raise AssertionError('development fixture cannot override cold source custody')
        retained = os.environ.get('HEPTA_HIA_PUBLICATION_MEASUREMENT_EVIDENCE')
        cls.temporary = None
        if retained:
            base = Path(retained)
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__
            cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-publication-measurement-')
            cls.folder = Path(cls.temporary.name)
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        cls.before = {path.relative_to(ROOT).as_posix(): path.read_bytes()
                      for folder in ('hepta', 'tools') for path in (ROOT / folder).rglob('*.py')}
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in',
                     'tests/test_hia_agent_installed_resources.py',
                     'tests/test_hia_publication_measurement_native.py',
                     'tests/fixtures/publication_measurement_698cc280.py.txt'):
            cls.before[name] = (ROOT / name).read_bytes()
        (cls.folder / 'source-before.json').write_text(json.dumps(
            {name: sha256(raw).hexdigest() for name, raw in cls.before.items()}, indent=2, sort_keys=True) + '\n')
        from tools.build_hia_publication_measurement import build
        if cold:
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'candidate', cls.compiler, Path(cold))
        else:
            if development:
                cls.compiler = Path(development)
            else:
                from tools.qualify_hia_selfhost import build_seed, compile_stage
                seed, _ = build_seed(cls.folder)
                source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
                first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
                cls.compiler, _ = compile_stage(cls.folder, 'B2', first, source)
                if first.read_bytes() != cls.compiler.read_bytes():
                    raise AssertionError('development compiler fixed point differs')
            cls.manifest = build(cls.folder / 'candidate', cls.compiler, development=True)
        cls.image = installed_publication_measurement(str(cls.manifest))
        cls.compiler_bytes = cls.compiler.read_bytes()
        cls.original = staticmethod(original_policy())
        cls.rows = []
        cls.integration_rows = []

    @classmethod
    def tearDownClass(cls):
        stable = (all((ROOT / name).read_bytes() == raw for name, raw in cls.before.items())
                  and cls.compiler.read_bytes() == cls.compiler_bytes)
        (cls.folder / 'differential.json').write_text(json.dumps({
            'schema': 'hepta.hia.publication-measurement-differential.v1',
            'original_source_git_blob': '698cc280566c74ba409f566b654e6ccdfa33eb2d',
            'original_function_sha256': FIXTURE_SHA256,
            'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
            'image_sha256': cls.image.image_sha256,
            'observations': cls.rows,
            'installation_and_scope_observations': cls.integration_rows,
            'source_and_compiler_unchanged': stable,
            'all_input_equivalence_proved': False, 'whole_stack_rewritten_in_hia': False,
        }, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('publication measurement source or compiler changed')

    def compare(self, value, prepare=0):
        expected = outcome(self.original, value, prepare)
        actual = outcome(self.image.assess, value, prepare)
        self.assertEqual(actual, expected)
        raw = packet(value, prepare)
        self.rows.append({'input_sha256': sha256(raw).hexdigest(), 'input_bytes': len(raw),
                          'prepare_ns': prepare, 'outcome': actual})
        return actual

    def test_each_allowed_odd_sample_count_and_ceil_remainder_boundaries(self):
        for count in range(15, 64, 2):
            self.compare(measurement(samples=count, baseline=60_000_000_000,
                                     candidate=59_000_000_001, calls_per_sample=64_000_000,
                                     horizon_calls=1_000_000_000_000), 999)
        for count in (1, 2, 3, 7, 63_999_999, 64_000_000):
            for horizon in (1, count - 1 or 1, count, count + 1, 1_000_000_000_000):
                self.compare(measurement(baseline=60_000_000_000, candidate=31_415_926_535,
                                         calls_per_sample=count, horizon_calls=horizon), 0)

    def test_complete_ordered_refusal_reasons_and_signed_saving_deviation(self):
        value = measurement(after_artifact_sha256='a' * 64, maximum_search_ns=1, horizon_calls=1)
        value['samples'] = [{'baseline_ns': (i % 3 + 1) * 1_000_000,
                             'candidate_ns': (i % 3 + 2) * 1_000_000} for i in range(15)]
        self.assertEqual(self.compare(value)[1]['reasons'], [
            'identical_native_artifacts', 'baseline_timing_noise', 'candidate_timing_noise',
            'insufficient_measured_gain', 'paired_saving_not_above_noise_margin',
            'search_cost_budget', 'experiment_cost_not_recovered'])
        for delta in (-60_000_000_000 + 1, -1, 0, 1, 60_000_000_000 - 1):
            baseline, candidate = (1, 1 - delta) if delta < 0 else (1 + delta, 1)
            self.compare(measurement(baseline=baseline, candidate=candidate, horizon_calls=1), 0)

    def test_projection_finite_limits_and_arbitrary_exact_preparation_integer(self):
        value = measurement(baseline=1, candidate=60_000_000_000,
                            horizon_calls=1_000_000_000_000)
        projection = 60_000_000_000_000_000_000_000
        for target in (-1, 0, 1, 2, 10**18 - 1, 10**18, 10**18 + 1):
            self.compare(value, target - projection - 2_000_000_000)
        for prepare in (0, -1, (1 << 63) - 1, 1 << 63, 1 << 64,
                        (1 << 80) - 1, 1 << 80, (1 << 80) + 1, 1 << 300,
                        -((1 << 80) - 1), -(1 << 80), -(1 << 300)):
            self.compare(measurement(), prepare)
        for baseline in (999_999, 1_000_000, 1_000_001):
            self.compare(measurement(baseline=baseline, candidate=1,
                                     horizon_calls=1_000_000_000_000), 0)

    def test_every_fixed_threshold_equality_and_immediate_neighbors(self):
        for difference in (19_999, 20_000, 20_001):
            self.compare(measurement(candidate=1_000_000 - difference), 0)
        for deviation in (49_999, 50_000, 50_001):
            value = measurement()
            value['samples'] = [{'baseline_ns': 1_000_000 + ((i % 3) - 1) * deviation,
                                 'candidate_ns': 500_000 + ((i % 3) - 1) * (deviation // 2)}
                                for i in range(15)]
            self.compare(value)
        for prepare in (-1, 0, 1):
            self.compare(measurement(maximum_search_ns=2_000_000_000), prepare)

    def test_deterministic_full_domain_native_differentials_preserve_frozen_object(self):
        randomizer = random.Random(0x484941)
        for _ in range(500):
            value = measurement(samples=randomizer.randrange(7, 32) * 2 + 1,
                calls_per_sample=randomizer.choice((1, 3, 64_000_000, randomizer.randrange(1, 64_000_001))),
                horizon_calls=randomizer.choice((1, 1_000_000_000_000, randomizer.randrange(1, 1_000_000_000_001))),
                search_cost_ns=randomizer.randrange(3_600_000_000_001),
                maximum_search_ns=randomizer.randrange(1, 3_600_000_000_001))
            value['samples'] = [{'baseline_ns': randomizer.randrange(1, 60_000_000_001),
                                 'candidate_ns': randomizer.randrange(1, 60_000_000_001)} for _ in value['samples']]
            before = copy.deepcopy(value)
            self.compare(value, randomizer.choice((0, -1, 1 << 300, randomizer.randrange(-10**20, 10**20))))
            self.assertEqual(value, before)

    def test_real_machine_matches_independent_vm_bytes_with_canaries(self):
        vm = VM()
        cases = [(measurement(samples=15), 7),
                 (measurement(samples=63, baseline=60_000_000_000, candidate=31_415_926_535,
                              calls_per_sample=64_000_000, horizon_calls=1_000_000_000_000), 0),
                 (measurement(baseline=1, candidate=60_000_000_000, horizon_calls=1_000_000_000_000),
                  1 - 60_000_000_000_000_000_000_000 - 2_000_000_000)]
        for value, prepare in cases:
            raw = packet(value, prepare)
            self.assertEqual(native_call(self.image, raw), vm.call(raw))
            self.compare(value, prepare)

    def test_strict_packet_custody_and_unchanged_full_u64_return(self):
        raw = packet(measurement(), 0)
        for length in (0, 79, 207, 447, len(raw) - 1):
            self.assertEqual(native_call(self.image, raw[:length])[0], 0xfffffffd)
        for index, value in ((0, 0), (8, 16), (16, 0), (24, 0), (32, 3_600_000_000_001),
                             (40, 0), (48, 2), (64, 65536), (72, 2), (208, 0), (216, 60_000_000_001)):
            changed = bytearray(raw)
            struct.pack_into('<Q', changed, index, value)
            words = self.image.observe(bytes(changed))
            self.assertEqual(words[1], 2)
        changed = bytearray(raw)
        changed[80] = ord('G')
        self.assertEqual(self.image.observe(bytes(changed))[1], 2)
        original_entry = self.image._entry
        def upper_bits(*arguments):
            return original_entry(*arguments) | (1 << 32)
        with patch.object(self.image, '_entry', upper_bits):
            with self.assertRaisesRegex(RuntimeError, 'ABI'):
                self.image.assess(measurement(), prepare_ns=0)

    def test_selected_original_public_entry_forbids_reference_and_median(self):
        value = measurement()
        expected = self.original(value, prepare_ns=37)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(owner, '_reference_assess_measurement', side_effect=AssertionError('host policy')),
              patch.object(owner, 'median', side_effect=AssertionError('host median'))):
            self.assertEqual(owner._assess_measurement(value, prepare_ns=37), expected)
            self.assertEqual(owner._assess_measurement(measurement(horizon_calls=1), prepare_ns=0)['eligible'], False)

    def test_original_measurement_policy_controls_under_selected_owner(self):
        from tests.test_hia_native_profile_convergence import NativeMeasurementPolicyTests
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeMeasurementPolicyTests)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(owner, '_reference_assess_measurement', side_effect=AssertionError('host policy')),
              patch.object(owner, 'median', side_effect=AssertionError('host median'))):
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        (self.folder / 'original-policy-controls.log').write_text(stream.getvalue())
        self.assertEqual(result.testsRun, 2)
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual((result.skipped, result.expectedFailures, result.unexpectedSuccesses), ([], [], []))

    def test_empty_missing_changed_source_selection_never_falls_back(self):
        with patch.object(owner, '_reference_assess_measurement', side_effect=AssertionError('host fallback')):
            with patch.dict(os.environ, {SELECTOR: ''}):
                with self.assertRaisesRegex(ValueError, 'must not be empty'):
                    owner._assess_measurement(measurement(), prepare_ns=0)
            with patch.dict(os.environ, {SELECTOR: str(self.folder / 'missing.json')}):
                with self.assertRaises(FileNotFoundError):
                    owner._assess_measurement(measurement(), prepare_ns=0)
            with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(Path, 'read_bytes', return_value=b'changed source'):
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    owner._assess_measurement(measurement(), prepare_ns=0)

    def test_builder_rejects_actual_compile_receipt_pollution_before_manifest(self):
        from tools import build_hia_publication_measurement as builder
        candidate = self.manifest.parent
        good_report = json.loads((candidate / 'build.json').read_bytes())
        full_output = (candidate / 'publication-measurement.output.bin').read_bytes()
        image = (candidate / 'publication-measurement.image.bin').read_bytes()
        changes = ({'abi_status': 1}, {'result_u64': len(image) | (1 << 32)},
                   {'source_unchanged': False}, {'output_sha256': '0' * 64})
        for index, change in enumerate(changes):
            destination = self.folder / ('bad-receipt-' + str(index))
            def copied(directory, _label, _compiler, _source):
                target = directory / 'publication-measurement.image.bin'
                target.write_bytes(image)
                (directory / 'publication-measurement.output.bin').write_bytes(full_output)
                return target, {**good_report['native_compile_receipt'], **change}
            with patch.object(builder, 'compile_stage', copied):
                with self.assertRaises(ValueError):
                    builder.build(destination, self.compiler, development=True)
            self.assertFalse((destination / 'manifest.json').exists())
            self.assertFalse((destination / 'build.json').exists())

    def test_build_requires_exactly_one_explicit_custody_mode(self):
        from tools.build_hia_publication_measurement import build
        for cold, development in ((None, False), (self.folder / 'absent', True), (None, 1)):
            destination = self.folder / ('invalid-mode-' + str(development))
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                build(destination, self.compiler, cold, development=development)
            self.assertFalse(destination.exists())

    def test_actual_installed_wheel_uses_HIA_and_rejects_warm_source_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        folder = self.folder / 'installed-publication-measurement'
        folder.mkdir()
        source = folder / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        def command(label, arguments):
            with (folder / (label + '.log')).open('xb') as output:
                result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=source,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, (folder / (label + '.log')).read_text())
        command('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
        archive, = (folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as handle:
            name, = (name for name in handle.getnames()
                     if name.endswith('/examples/hia_bootstrap/publication_measurement.hepta'))
            self.assertEqual(handle.extractfile(name).read(), SOURCE.read_bytes())
        command('wheel', ['-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation',
                          '--wheel-dir', folder / 'wheels', archive])
        wheel, = (folder / 'wheels').glob('*.whl')
        installed = folder / 'installed'
        command('install', ['-m', 'pip', 'install', '--no-index', '--no-deps', '--target', installed, wheel])
        value = measurement(baseline=60_000_000_000, candidate=31_415_926_535,
                            calls_per_sample=64_000_000, horizon_calls=1_000_000_000_000)
        request = folder / 'measurement.json'
        request.write_text(json.dumps({'measurement': value, 'prepare_ns': 37,
                                       'expected': self.original(value, prepare_ns=37)}))
        script = r'''
import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta import hia_multiversion as public
from hepta import hia_publication_measurement_native as native
assert Path(public.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert native.SOURCE == Path(sys.argv[1]) / 'hepta/_data/examples/hia_bootstrap/publication_measurement.hepta'
request = json.loads(Path(sys.argv[3]).read_bytes())
os.environ[native.SELECTOR] = sys.argv[2]
with patch.object(public, '_reference_assess_measurement', side_effect=AssertionError('installed path cannot use Python policy')), \
        patch.object(public, 'median', side_effect=AssertionError('installed path cannot use host median')):
    observed = public._assess_measurement(request['measurement'], prepare_ns=request['prepare_ns'])
    assert observed == request['expected']
    source = native.SOURCE.read_bytes()
    refusals = []
    try:
        for replacement in (source + b'\n', None):
            if replacement is None:
                native.SOURCE.unlink()
            else:
                native.SOURCE.write_bytes(replacement)
            try:
                public._assess_measurement(request['measurement'], prepare_ns=request['prepare_ns'])
            except (ValueError, FileNotFoundError) as error:
                refusals.append((type(error).__name__, str(error)))
            else:
                raise AssertionError('warm selected image concealed missing or changed package source')
    finally:
        native.SOURCE.write_bytes(source)
    assert refusals[0] == ('ValueError', 'native HIA JSON source identity mismatch')
    assert refusals[1][0] == 'FileNotFoundError'
print(json.dumps({'actual_result': observed, 'installed_source': str(native.SOURCE),
                  'warm_source_refusals': refusals, 'python_policy_fallback': False}, sort_keys=True))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed),
                                 str(self.manifest), str(request)], cwd=folder, capture_output=True, timeout=20)
        (folder / 'installed.stdout.bin').write_bytes(result.stdout)
        (folder / 'installed.stderr.bin').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.integration_rows.append({'case': 'actual-sdist-wheel-installed-publication-measurement',
            'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(), 'observations': json.loads(result.stdout)})

    def test_actual_pinned_helper_scope_rejects_other_thread_and_selection_drift(self):
        from hepta import hia_native_helpers as authority
        bundle = self.folder / 'publication-measurement-helpers.json'
        bundle.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
            'abi': authority.ABI, 'helpers': [{'selector': SELECTOR,
                'manifest_path': self.manifest.relative_to(self.folder).as_posix(),
                'manifest_sha256': sha256(self.manifest.read_bytes()).hexdigest()}]}))
        pin = sha256(bundle.read_bytes()).hexdigest()
        value = measurement()
        expected = self.original(value, prepare_ns=37)
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(owner, '_reference_assess_measurement', side_effect=AssertionError('pinned policy cannot fallback')),
              patch.object(owner, 'median', side_effect=AssertionError('pinned policy cannot use host median'))):
            with authority.native_helpers_scope(str(bundle), pin):
                self.assertEqual(owner._assess_measurement(value, prepare_ns=37), expected)
                refused = []
                def wrong_owner():
                    try:
                        owner._assess_measurement(value, prepare_ns=37)
                    except ValueError as error:
                        refused.append(str(error))
                worker = threading.Thread(target=wrong_owner)
                worker.start()
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(refused, ['native helper worker scope belongs to its original process and thread'])
                with patch.dict(os.environ, {SELECTOR: str(bundle)}):
                    with self.assertRaisesRegex(ValueError, 'outside the pinned worker bundle'):
                        owner._assess_measurement(value, prepare_ns=37)
                    with self.assertRaisesRegex(ValueError, 'selection changed'):
                        authority.native_helpers_identity()
                self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': pin})
            self.assertNotIn(SELECTOR, os.environ)
        self.integration_rows.append({'case': 'operator-pinned-publication-measurement-helper',
            'bundle_sha256': pin, 'actual_result': expected, 'foreign_thread_refused': True,
            'changed_selection_refused': True, 'terminal_selector_drift_refused': True,
            'environment_restored': True})


if __name__ == '__main__':
    unittest.main()
