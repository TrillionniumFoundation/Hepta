"""Frozen original verdicts, independent Core VM and actual native cost control."""
from __future__ import annotations

import builtins
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_full_cost_gate as owner
from hepta import hia_full_cost_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.test_hia_full_cost_gate import fixture, wire
from tools import generate_hia_full_cost as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/full_cost_0daf86d.py.txt'
FIXTURE_SHA = 'a6d8e5f7355089dc1071d9ce72a5c59973fe9610e31002a3d212176092fa3e49'


def original():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('independent original full-cost source changed')
    namespace = {'__name__': 'hepta.full_cost_frozen_reference', '__package__': 'hepta'}
    exec(compile(raw, str(FIXTURE), 'exec'), namespace)
    return namespace['assess_full_cost']


def observed(call):
    try:
        return 'returned', call()
    except Exception as exc:
        return 'raised', type(exc).__name__, str(exc)


def interpreted(program, raw):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(i + 1, bytearray(value)) for i, value in enumerate(
        (raw, b'\xa5' * native.OUTPUT_BYTES, b''))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'], [_View(value, i != 0) for i, value in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw or owners[2].data:
        raise AssertionError('Core VM changed immutable input or zero workspace')
    return code, bytes(owners[1].data)


def threshold_cases():
    cases = []
    for totals in ([8, 8, 8, 10**17], [10**17, 10**17, 10**17, 8],
                   [12, 12, 14, 15], [12, 12, 12, 12], [13, 11, 11, 8]):
        data = fixture()
        for arm, total in zip(data['arms'], (totals[0], totals[2], totals[1], totals[3])):
            arm['one_time_ns'] = dict.fromkeys(native.COSTS, 0)
            arm['one_time_ns']['candidate_build'] = total - 8
            for row in arm['observations']:
                row.update(execution_ns=1, controller_ns=0, failed_attempt_ns=0, p99_ns=1)
        cases.append(data)
    return cases


def packets():
    cases = [fixture(), *threshold_cases()]
    for data in cases:
        report = original()(wire(data))
        for arm in data['arms']:
            yield native.arm_packet(arm['one_time_ns'], arm['observations'])
        yield native.decision_packet(report['arm_total_ns'], report['arm_observed_limits'],
            report['unknown_costs'], {a['observer_digest'] for a in data['arms']}, data)


class FullCostSourceTests(unittest.TestCase):
    def test_source_reproduces_without_enlarging_compiler_profile(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        data = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(data['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in data['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for fn in data['functions'] for b in fn['blocks']), 8192)
        self.assertLessEqual(max(len(b['params']) for fn in data['functions'] for b in fn['blocks']), 16)
        original()

    def test_independent_VM_retains_exact_wide_negative_ppm_and_ties(self):
        program = assemble_program(native.SOURCE.read_bytes())
        for data in threshold_cases():
            expected = original()(wire(data))
            raw = native.decision_packet(expected['arm_total_ns'], expected['arm_observed_limits'],
                expected['unknown_costs'], {a['observer_digest'] for a in data['arms']}, data)
            code, output = interpreted(program, raw)
            self.assertEqual(code, native.OUTPUT_BYTES)
            words = struct.unpack('<10Q', output)
            self.assertEqual(native.ORDER[words[3]], expected['best_control'])
            magnitude = words[7] | (words[8] << 64)
            self.assertEqual(-magnitude if words[5] else magnitude, expected['ndu_saving_ppm'])
            self.assertEqual([v for bit, v in enumerate(native.REASONS) if words[9] & 1 << bit], expected['reasons'])

    def test_absent_selector_keeps_original_verdict_and_no_optional_import(self):
        real_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.endswith('hia_full_cost_native'):
                raise AssertionError('default imported native arithmetic')
            return real_import(name, *args, **kwargs)
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            with patch('builtins.__import__', guarded):
                for data in (fixture(), *threshold_cases()):
                    self.assertEqual(owner.assess_full_cost(wire(data)), original()(wire(data)))

    def test_invalid_admission_precedes_optional_native_image_loading(self):
        data = fixture()
        data['arms'][0]['observations'][0]['result_digest'] = '9' * 64
        with patch.dict(os.environ, {native.SELECTOR: '/must-not-open'}), \
                patch.object(native, 'installed_full_cost', side_effect=AssertionError('premature image')) as loading:
            self.assertEqual(observed(lambda: owner.assess_full_cost(wire(data))),
                             observed(lambda: original()(wire(data))))
        loading.assert_not_called()


class FullCostNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_full_cost import build
        evidence = os.environ.get('HEPTA_HIA_FULL_COST_EVIDENCE')
        cls.temporary = None
        if evidence is not None:
            if not evidence:
                raise ValueError('full-cost evidence selector must not be empty')
            cls.root = Path(evidence)
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-full-cost-')
            cls.root = Path(cls.temporary.name)
        cls.program = assemble_program(native.SOURCE.read_bytes())
        # Independently execute a wide signed ratio before constructing the image.
        sample = threshold_cases()[0]
        expected = original()(wire(sample))
        raw = native.decision_packet(expected['arm_total_ns'], expected['arm_observed_limits'],
            expected['unknown_costs'], {a['observer_digest'] for a in sample['arms']}, sample)
        if interpreted(cls.program, raw)[0] != native.OUTPUT_BYTES:
            raise AssertionError('independent VM rejected the admitted control')
        cold = os.environ.get('HEPTA_HIA_FULL_COST_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_FULL_COST_DEVELOPMENT_COMPILER')
        if cold is not None and development is not None:
            raise ValueError('choose matching cold custody or explicit development compiler')
        if cold is not None:
            if not cold:
                raise ValueError('full-cost cold selector must not be empty')
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        elif development is not None:
            if not development:
                raise ValueError('full-cost development compiler selector must not be empty')
            compiler = Path(development)
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
            seed, _ = build_seed(cls.root)
            compiler, _ = compile_stage(cls.root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
        cls.cold_report = cold
        cls.compiler = compiler
        cls.compiler_bytes = compiler.read_bytes()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_full_cost(str(cls.manifest))
        from tools.build_hia_patch_impact import build as build_patch
        cls.patch_manifest = build_patch(cls.root / 'patch-built', compiler, cold,
                                         development=cold is None)

    @classmethod
    def tearDownClass(cls):
        same = cls.compiler.read_bytes() == cls.compiler_bytes
        (cls.root / 'component-custody.json').write_text(json.dumps({
            'schema': 'hepta.hia.full-cost-test-custody.v1',
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'compiler_unchanged': same, 'manifest': str(cls.manifest),
            'patch_manifest': str(cls.patch_manifest),
            'matching_cold_report': cls.cold_report,
            'test_result_owned_by_outer_runner': True,
        }, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not same:
            raise AssertionError('native full-cost compiler bytes changed')

    def frame(self, raw, *, output_bytes=native.OUTPUT_BYTES, workspace_bytes=0):
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        output = ctypes.create_string_buffer(b'\xa5' * (native.OUTPUT_BYTES + 16), native.OUTPUT_BYTES + 16)
        scratch = ctypes.create_string_buffer(b'\x91' * 16, 16)
        code = self.image._entry(source, len(raw), output, output_bytes, scratch, workspace_bytes)
        self.assertEqual(source.raw, raw or b'\0')
        self.assertEqual(output.raw[native.OUTPUT_BYTES:], b'\xa5' * 16)
        self.assertEqual(scratch.raw, b'\x91' * 16)
        return code, output.raw[:native.OUTPUT_BYTES]

    def test_native_machine_complete_buffers_match_independent_VM(self):
        # Avoid multiplying equal arm packets; retain every distinct observation.
        for raw in dict.fromkeys(packets()):
            with self.subTest(packet_sha256=sha256(raw).hexdigest()):
                self.assertEqual(self.frame(raw), interpreted(self.program, raw))

    def test_actual_public_entry_forbids_original_arithmetic(self):
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                patch.object(owner, '_reference_arm', side_effect=AssertionError('host sum/peak entered')), \
                patch.object(owner, '_reference_decision', side_effect=AssertionError('host ratio/decision entered')):
            for data in (fixture(), *threshold_cases()):
                self.assertEqual(owner.assess_full_cost(wire(data)), original()(wire(data)))

    def test_all_six_reasons_and_best_control_tie_order(self):
        data = fixture()
        for arm in data['arms']:
            arm['unknown_costs'] = ['unmeasured']
            arm['one_time_ns'] = dict.fromkeys(native.COSTS, 0)
            for row in arm['observations']:
                row.update(execution_ns=1, controller_ns=0, failed_attempt_ns=0)
        data['arms'][3]['one_time_ns']['verification'] = 2
        data['arms'][1]['observer_digest'] = '9' * 64
        data.update(maximum_peak_rss_bytes=1, maximum_p99_ns=1)
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
            report = owner.assess_full_cost(wire(data))
        self.assertEqual(report, original()(wire(data)))
        self.assertEqual(report['reasons'], list(native.REASONS))
        self.assertEqual(report['best_control'], 'baseline')
        data['arms'][0]['one_time_ns']['search'] = 1
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
            self.assertEqual(owner.assess_full_cost(wire(data))['best_control'], 'dp')

    def test_full_original_128_trial_and_total_boundary(self):
        data = fixture()
        data['registered_trials'] = [{**data['registered_trials'][0], 'id': 't%03d' % i} for i in range(128)]
        for arm in data['arms']:
            original_row = arm['observations'][0]
            arm['observations'] = [{**original_row, 'trial_id': trial['id'], 'execution_ns': 1,
                                   'controller_ns': 0, 'failed_attempt_ns': 0} for trial in data['registered_trials']]
            arm['one_time_ns'] = dict.fromkeys(native.COSTS, 0)
            arm['one_time_ns']['verification'] = 10**17 - 128
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
            self.assertEqual(owner.assess_full_cost(wire(data)), original()(wire(data)))
            data['arms'][0]['one_time_ns']['verification'] += 1
            data['arms'][0]['unknown_costs'] = ['duplicate', 'duplicate']
            self.assertEqual(observed(lambda: owner.assess_full_cost(wire(data))),
                             observed(lambda: original()(wire(data))))
            # Numeric/type admission still precedes total refusal as originally.
            data['arms'][0]['observations'][-1]['p99_ns'] = True
            self.assertEqual(observed(lambda: owner.assess_full_cost(wire(data))),
                             observed(lambda: original()(wire(data))))

    def test_exact_ratios_wide_products_and_negative_floor(self):
        rng = random.Random(0xC057)
        data = fixture()
        peaks = {name: {'peak_rss_bytes': 1, 'p99_ns': 1} for name in native.ORDER}
        unknown = {name: [] for name in native.ORDER}
        for _ in range(120):
            totals = {name: rng.randrange(8, 10**17 + 1) for name in native.ORDER}
            data['minimum_gain_ns'] = rng.randrange(1, 10**17 + 1)
            data['minimum_gain_ppm'] = rng.randrange(1, 1_000_001)
            self.assertEqual(self.image.decide(totals, peaks, unknown, {'x'}, data),
                             owner._reference_decision(totals, peaks, unknown, {'x'}, data))
        for best, ndu in ((8, 10**17), (13, 17), (10**17, 8), (31, 30)):
            totals = dict.fromkeys(native.ORDER, best); totals['ndu'] = ndu
            actual = self.image.decide(totals, peaks, unknown, {'x'}, data)
            self.assertEqual(actual[2], (best - ndu) * 1_000_000 // best)

    def test_refused_transport_and_capacity_never_publish_output(self):
        good = native.arm_packet(fixture()['arms'][0]['one_time_ns'], fixture()['arms'][0]['observations'])
        bad = [b'', good[:-1], good + b'\0', b'\0' * len(good)]
        for index, value in ((8, 99), (16, 129), (24, 10**17 + 1), (112, 0), (136, (1 << 48) + 1)):
            changed = bytearray(good); struct.pack_into('<Q', changed, index, value); bad.append(bytes(changed))
        for raw in bad:
            self.assertEqual(self.frame(raw), (3, b'\xa5' * native.OUTPUT_BYTES))
        self.assertEqual(self.frame(good, output_bytes=native.OUTPUT_BYTES - 1), (3, b'\xa5' * native.OUTPUT_BYTES))
        self.assertEqual(self.frame(good, workspace_bytes=1), (3, b'\xa5' * native.OUTPUT_BYTES))

    def test_actual_installed_wheel_uses_its_own_source_and_rejects_mutation(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        self.assertIn('examples/hia_bootstrap/full_cost.hepta', RESOURCES)
        self.assertIn('examples/hia_bootstrap/patch_impact.hepta', RESOURCES)
        folder = self.root / 'installation'; folder.mkdir()
        source = folder / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels = folder / 'wheels'
        environment = {key: value for key, value in os.environ.items()
                       if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        def run(arguments, cwd=source):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=cwd,
                env=environment, capture_output=True, text=True, timeout=60)
            if result.returncode:
                self.fail(result.stdout + result.stderr)
            return result
        run(['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', wheels, source])
        wheel, = wheels.glob('*.whl')
        installed = folder / 'installed'
        run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel])
        data = folder / 'input.json'; data.write_bytes(wire(threshold_cases()[0]))
        from hepta import hia_patch_impact as impact
        from tests.test_hia_patch_impact import (append_wrapper, isolated_program,
                                               move_program, patch_packet, patch_initial_byte)
        patch_manifest = self.patch_manifest
        program = move_program()
        append_wrapper(program, 'wrapper', 'move_bytes')
        append_wrapper(program, 'top', 'wrapper')
        isolated_program(program)
        request = patch_packet(program, patch_initial_byte(program))
        patch_input = folder / 'patch.json'
        patch_input.write_text(json.dumps({'program': program, 'request': request}))
        with patch.dict(os.environ):
            os.environ.pop('HEPTA_HIA_PATCH_IMPACT_MANIFEST', None)
            candidate, receipt, report = impact.analyze_patch_impact(program, request)
        patch_expected = {'candidate': candidate.as_dict(), 'receipt': receipt, 'impact': report}
        script = r'''import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from hepta import hia_full_cost_gate as owner
from hepta import hia_full_cost_native as native
from hepta import hia_patch_impact as impact
from hepta import hia_patch_impact_native as impact_native
assert Path(owner.__file__).is_relative_to(Path(sys.argv[1]))
assert native.SOURCE.is_relative_to(Path(sys.argv[1]))
assert impact_native.SOURCE.is_relative_to(Path(sys.argv[1]))
def forbidden(*args, **kwargs): raise AssertionError("installed reference fallback")
owner._reference_arm = owner._reference_decision = forbidden
impact._reference_changes = impact._reference_graph = impact._incoming = forbidden
os.environ[impact_native.SELECTOR] = sys.argv[5]
os.environ[native.SELECTOR] = sys.argv[2]
raw = Path(sys.argv[3]).read_bytes()
payload = json.loads(Path(sys.argv[6]).read_bytes())
def patch_result():
    candidate, receipt, report = impact.analyze_patch_impact(payload['program'], payload['request'])
    return {'candidate': candidate.as_dict(), 'receipt': receipt, 'impact': report}
if sys.argv[4] == 'accept':
    print(json.dumps({'cost': owner.assess_full_cost(raw), 'patch': patch_result()}, sort_keys=True))
else:
    try:
        if sys.argv[4] == 'cost-reject': owner.assess_full_cost(raw)
        else: patch_result()
    except ValueError as error:
        assert 'source identity mismatch' in str(error), str(error)
        print('REFUSED_CHANGED_INSTALLED_SOURCE')
    else: raise AssertionError('changed packaged source accepted')
'''
        accepted = run(['-I', '-c', script, installed, self.manifest, data, 'accept', patch_manifest, patch_input], cwd=folder)
        self.assertEqual(json.loads(accepted.stdout), {'cost': original()(data.read_bytes()), 'patch': patch_expected})
        packaged = installed / 'hepta/_data/examples/hia_bootstrap/full_cost.hepta'
        original_source = packaged.read_bytes()
        packaged.write_bytes(original_source + b'\n')
        rejected = run(['-I', '-c', script, installed, self.manifest, data, 'cost-reject', patch_manifest, patch_input], cwd=folder)
        self.assertEqual(rejected.stdout.strip(), 'REFUSED_CHANGED_INSTALLED_SOURCE')
        packaged.write_bytes(original_source)
        patch_source = installed / 'hepta/_data/examples/hia_bootstrap/patch_impact.hepta'
        patch_source.write_bytes(patch_source.read_bytes() + b'\n')
        rejected = run(['-I', '-c', script, installed, self.manifest, data, 'patch-reject', patch_manifest, patch_input], cwd=folder)
        self.assertEqual(rejected.stdout.strip(), 'REFUSED_CHANGED_INSTALLED_SOURCE')

    def test_pinned_two_owner_bundle_real_callers_restoration_and_drift(self):
        from hepta import hia_patch_impact as impact
        from hepta import hia_patch_impact_native as impact_native
        from hepta.hia_native_helpers import (ABI, SCHEMA, TARGET,
                                             native_helpers_identity, native_helpers_scope)
        from tests.test_hia_patch_impact import (append_wrapper, isolated_program,
                                               move_program, patch_packet, patch_initial_byte)
        folder = self.root / 'pinned-bundle'; folder.mkdir()
        clean = {key: value for key, value in os.environ.items()
                 if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        # Empty preexisting keys are part of the original namespace and must
        # be restored after success, drift detection and failed admission.
        clean.update({native.SELECTOR: '', impact_native.SELECTOR: '',
                      'HEPTA_HIA_TEST_RESTORE_MANIFEST': ''})
        entries, sources, manifests = [], [], []
        for label, module, original_manifest in (
                ('cost', native, self.manifest), ('impact', impact_native, self.patch_manifest)):
            source = folder / (label + '.hepta')
            source.write_bytes(module.SOURCE.read_bytes())
            record = json.loads(original_manifest.read_bytes())
            image = folder / (label + '.image.bin')
            image.write_bytes((original_manifest.parent / record['image_path']).read_bytes())
            record['image_path'] = image.name
            manifest = folder / (label + '.json')
            manifest.write_text(json.dumps(record, sort_keys=True))
            entries.append({'selector': module.SELECTOR, 'manifest_path': manifest.name,
                            'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()})
            sources.append(source); manifests.append(manifest)
        bundle = folder / 'helpers.json'
        bundle.write_text(json.dumps({'schema': SCHEMA, 'target': TARGET, 'abi': ABI,
                                      'helpers': entries}, sort_keys=True))
        bundle_sha = sha256(bundle.read_bytes()).hexdigest()
        program = move_program()
        append_wrapper(program, 'wrapper', 'move_bytes')
        append_wrapper(program, 'top', 'wrapper')
        isolated_program(program)
        request = patch_packet(program, patch_initial_byte(program))
        cost_raw = wire(threshold_cases()[0])
        cost_expected = original()(cost_raw)
        with patch.dict(os.environ, {key: value for key, value in clean.items()
                                    if key not in (native.SELECTOR, impact_native.SELECTOR)}, clear=True):
            candidate, receipt, report = impact.analyze_patch_impact(program, request)
        patch_expected = candidate.as_dict(), receipt, report
        with patch.dict(os.environ, clean, clear=True), \
                patch.object(native, 'SOURCE', sources[0]), \
                patch.object(impact_native, 'SOURCE', sources[1]), \
                patch.object(owner, '_reference_arm', side_effect=AssertionError('bundle host arithmetic')), \
                patch.object(owner, '_reference_decision', side_effect=AssertionError('bundle host decision')), \
                patch.object(impact, '_reference_changes', side_effect=AssertionError('bundle host changes')), \
                patch.object(impact, '_reference_graph', side_effect=AssertionError('bundle host graph')), \
                patch.object(impact, '_incoming', side_effect=AssertionError('bundle host incoming')):
            before = dict(os.environ)
            with native_helpers_scope(str(bundle), bundle_sha):
                with patch('hepta.hia_json_preflight_native._load_manifest',
                           side_effect=AssertionError('pinned bundle used general loader')):
                    self.assertEqual(owner.assess_full_cost(cost_raw), cost_expected)
                    actual_candidate, actual_receipt, actual_report = impact.analyze_patch_impact(program, request)
                    self.assertEqual((actual_candidate.as_dict(), actual_receipt, actual_report), patch_expected)
                self.assertEqual(native_helpers_identity(), {'native_helpers_sha256': bundle_sha})
                source_raw = sources[0].read_bytes()
                try:
                    sources[0].write_bytes(source_raw + b'\n')
                    with self.assertRaisesRegex(ValueError, 'inputs changed'):
                        native_helpers_identity()
                finally:
                    sources[0].write_bytes(source_raw)
            self.assertEqual(dict(os.environ), before)
            self.assertEqual(native_helpers_identity(), {})
            with native_helpers_scope(str(bundle), bundle_sha):
                manifest_raw = manifests[1].read_bytes()
                try:
                    manifests[1].write_bytes(manifest_raw + b'\n')
                    with self.assertRaisesRegex(ValueError, 'inputs changed'):
                        native_helpers_identity()
                finally:
                    manifests[1].write_bytes(manifest_raw)
            self.assertEqual(dict(os.environ), before)
            # A subsequent request cannot admit either changed source bytes or
            # an unpinned child manifest even though its JSON remains parseable.
            for target, reason in ((sources[1], 'source identity mismatch'),
                                   (manifests[0], 'manifest identity mismatch')):
                raw = target.read_bytes()
                try:
                    target.write_bytes(raw + b'\n')
                    with self.assertRaisesRegex(ValueError, reason):
                        with native_helpers_scope(str(bundle), bundle_sha):
                            self.fail('changed administrator bundle input admitted')
                finally:
                    target.write_bytes(raw)
                self.assertEqual(dict(os.environ), before)
                self.assertEqual(native_helpers_identity(), {})
            # Scope locks and owner state must also be reusable after refusal.
            with native_helpers_scope(str(bundle), bundle_sha):
                self.assertEqual(owner.assess_full_cost(cost_raw), cost_expected)
                self.assertEqual(native_helpers_identity(), {'native_helpers_sha256': bundle_sha})
            self.assertEqual(dict(os.environ), before)

    def test_invalid_or_empty_selection_never_calls_reference(self):
        with patch.object(owner, '_reference_arm', side_effect=AssertionError('host arithmetic fallback')):
            for selected in ('', '/does-not-exist/full-cost-manifest.json'):
                with patch.dict(os.environ, {native.SELECTOR: selected}):
                    with self.assertRaises((ValueError, OSError)):
                        owner.assess_full_cost(wire(fixture()))


if __name__ == '__main__':
    unittest.main()
