"""Real no-selector candidate installation, default worker custody and callers."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_DEFAULT_RELEASE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_DEFAULT_RELEASE_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_DEFAULT_RELEASE_EVIDENCE'


def clean_environment():
    return {**{key: value for key, value in os.environ.items()
               if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')},
            'PYTHONDONTWRITEBYTECODE': '1'}


class DefaultReleaseSourceTests(unittest.TestCase):
    def test_portable_pin_retains_original_api_on_other_host_observations(self):
        from hepta.hia_default_native import capture_default_bundle, render_pin
        from hepta.hia_full_cost_gate import assess_full_cost
        from tests.test_hia_full_cost_native import fixture, wire, original
        self.assertEqual((ROOT / 'hepta/hia_default_native_pin.py').read_bytes(), render_pin(None))
        with patch.dict(os.environ, clean_environment(), clear=True), \
             patch('hepta.hia_native_helpers.NativeHelpersBinding', side_effect=AssertionError('native binding')):
            for system, machine in (('Windows', 'AMD64'), ('Darwin', 'arm64'), ('Linux', 'aarch64')):
                with patch('platform.system', return_value=system), patch('platform.machine', return_value=machine):
                    self.assertIsNone(capture_default_bundle())
                    self.assertEqual(assess_full_cost(wire(fixture())), original()(wire(fixture())))

    def test_portable_worker_scope_is_still_unselected(self):
        from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope() as selected:
            self.assertIsNone(selected)
            self.assertEqual(native_helpers_identity(), {})

    def test_invalid_cold_or_missing_choice_cannot_create_candidate_output(self):
        from tools.build_hia_default_release import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold.json'
            compiler.write_bytes(b'not a compiler')
            cold.write_text('{}')
            for arguments in ({}, {'cold_report': cold}, {'cold_report': cold, 'development': True}):
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    build(root / 'must-not-exist', compiler, **arguments)
                self.assertFalse((root / 'must-not-exist').exists())

    def test_pin_value_cannot_change_without_its_captured_declaration(self):
        from hepta import hia_default_native_pin
        from hepta.hia_default_native import capture_default_bundle, PIN_SCHEMA, TARGET, BUNDLE_RESOURCE
        candidate = (PIN_SCHEMA, TARGET, BUNDLE_RESOURCE, 'a' * 64,
                     'DEVELOPMENT_COMPONENT', '-', 'b' * 64)
        with patch.object(hia_default_native_pin, 'RELEASE_PIN', candidate), \
             patch('hepta.hia_native_helpers.NativeHelpersBinding', side_effect=AssertionError('native binding')):
            with self.assertRaisesRegex(ValueError, 'pin'):
                capture_default_bundle()


PRELUDE = r'''
import importlib.abc, json, os, sys
from pathlib import Path
from unittest.mock import patch
installed = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(installed))
assert not [key for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
class NoAuthoringImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'tools' or fullname.startswith('tools.'):
            raise AssertionError('installed runtime imported authoring: ' + fullname)
sys.meta_path.insert(0, NoAuthoringImports())
from hepta import hia_full_cost_gate as owner
from hepta import hia_full_cost_native as native
from hepta import hia_default_native as defaults
from hepta import hia_native_helpers as helpers
assert Path(owner.__file__).resolve().is_relative_to(installed)
assert Path(native.__file__).resolve().is_relative_to(installed)
assert native.SOURCE.resolve().is_relative_to(installed)
raw = Path(sys.argv[2]).read_bytes()
def forbidden(*args, **kwargs):
    raise AssertionError('retained arithmetic or unpinned loader entered')
owner._reference_arm = owner._reference_decision = forbidden
'''


class DefaultReleaseNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_default_release import build
        from tools.build_hia_patch_impact import build as build_patch
        from tests.test_hia_full_cost_native import original, threshold_cases, wire, interpreted
        from hepta.hia_agent_assembly import assemble_program
        from hepta import hia_full_cost_native as native
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if ((cold is None) == (development is None) or cold == '' or development == ''):
            raise ValueError('default-release tests require one current cold report or explicit development compiler')
        evidence = os.environ.get(EVIDENCE)
        if evidence is not None:
            if not evidence:
                raise ValueError('default-release evidence directory must not be empty')
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-default-release-')
            cls.root = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        if cold:
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        # Observe both unchanged arithmetic protocols in the independent VM
        # before constructing any package image. Detailed numerical coverage
        # remains in the retained full-cost component and original caller suites.
        document = threshold_cases()[0]
        expected = original()(wire(document))
        program = assemble_program(native.SOURCE.read_bytes())
        arm = document['arms'][0]
        requests = (native.arm_packet(arm['one_time_ns'], arm['observations']),
                    native.decision_packet(expected['arm_total_ns'], expected['arm_observed_limits'],
                        expected['unknown_costs'], {a['observer_digest'] for a in document['arms']}, document))
        for request in requests:
            code, result = interpreted(program, request)
            if code != native.OUTPUT_BYTES or len(result) != native.OUTPUT_BYTES:
                raise AssertionError('independent full-cost VM did not admit the original protocol')
        cls.wheel = build(cls.root / 'build', compiler, cold, development=not bool(cold))
        cls.report = json.loads((cls.root / 'build/build.json').read_bytes())
        cls.patch_manifest = build_patch(cls.root / 'other-owner', compiler, cold, development=not bool(cold))
        cls.installed = cls.root / 'installed'
        cls.environment = clean_environment()
        cls.input = cls.root / 'input.json'
        cls.input.write_bytes(wire(threshold_cases()[0]))
        cls.expected = original()(cls.input.read_bytes())
        cls._run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                  '--target', cls.installed, cls.wheel])
        cls.initial_files = cls.inventory()

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        from tools.build_hia_default_release import encoded
        record = {'schema': 'hepta.hia.default-native-release-test-custody.v1',
            'scope': cls.report['scope'], 'source_manifest_before': cls.report['source_manifest'],
            'source_manifest_after': current_sources(), 'compiler_sha256': cls.report['compiler_sha256'],
            'cold_report_sha256': cls.report['cold_report_sha256'], 'wheel': str(cls.wheel),
            'wheel_sha256': sha256(cls.wheel.read_bytes()).hexdigest(),
            'package_build_sha256': sha256((cls.root / 'build/build.json').read_bytes()).hexdigest(),
            'default_bundle_sha256': cls.report['default_bundle_sha256'],
            'installed_files_before': cls.initial_files, 'installed_files_after': cls.inventory(),
            'source_and_installation_unchanged': (current_sources() == cls.report['source_manifest']
                and cls.inventory() == cls.initial_files),
            'independent_VM_both_protocols_before_image_construction': True,
            'retained_reference_bodies_removed': False, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record))
        if not record['source_and_installation_unchanged']:
            raise ValueError('default-release source or installation changed during execution')

    @classmethod
    def _run(cls, arguments, *, env=None, input=None):
        result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=cls.root,
            env=env or cls.environment, input=input, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    @classmethod
    def child(cls, body, *arguments, env=None):
        return cls._run(['-I', '-c', PRELUDE + body, cls.installed, cls.input, *arguments], env=env)

    @classmethod
    def inventory(cls):
        return {str(p.relative_to(cls.installed)): sha256(p.read_bytes()).hexdigest()
                for p in sorted(cls.installed.rglob('*')) if p.is_file()}

    def tearDown(self):
        self.assertEqual(self.inventory(), self.initial_files)

    def test_wheel_is_platform_specific_and_only_pin_is_derived_runtime_source(self):
        import csv
        import io
        import base64
        from hepta.hia_default_native import render_pin
        with zipfile.ZipFile(self.wheel) as archive:
            names = archive.namelist()
            metadata, = [name for name in names if name.endswith('.dist-info/WHEEL')]
            self.assertIn(b'Root-Is-Purelib: false\n', archive.read(metadata))
            self.assertIn(b'Tag: py3-none-linux_x86_64\n', archive.read(metadata))
            self.assertEqual(archive.read('hepta/hia_default_native_pin.py'), render_pin(tuple(self.report['pin'])))
            for name in names:
                if name.startswith('hepta/') and name.endswith('.py') and '/_data/' not in name:
                    if name != 'hepta/hia_default_native_pin.py':
                        self.assertEqual(archive.read(name), (ROOT / name).read_bytes(), name)
            record, = [name for name in names if name.endswith('.dist-info/RECORD')]
            rows = list(csv.reader(io.StringIO(archive.read(record).decode())))
            self.assertEqual({row[0] for row in rows}, set(names))
            for name, digest, length in rows:
                if name != record:
                    expected = base64.urlsafe_b64encode(sha256(archive.read(name)).digest()).rstrip(b'=').decode()
                    self.assertEqual(digest, 'sha256=' + expected)
                    self.assertEqual(int(length), len(archive.read(name)))
        self.assertFalse(self.report['ordinary_source_default_changed'])
        self.assertFalse(self.report['retained_reference_bodies_removed'])

    def test_ordinary_installed_API_needs_no_selector_or_authoring_imports(self):
        body = r'''
counts = [0, 0]
arm, decide = native.NativeFullCost.arm, native.NativeFullCost.decide
def seen_arm(image, *args):
    assert getattr(image, '_default_package_binding', None) is not None
    counts[0] += 1
    return arm(image, *args)
def seen_decide(image, *args):
    counts[1] += 1
    return decide(image, *args)
with patch.object(native.NativeFullCost, 'arm', seen_arm), \
     patch.object(native.NativeFullCost, 'decide', seen_decide), \
     patch('hepta.hia_json_preflight_native._load_manifest', forbidden):
    answer = owner.assess_full_cost(raw)
assert counts == [4, 1], counts
assert not [k for k in os.environ if k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST')]
print(json.dumps(answer, sort_keys=True))
'''
        self.assertEqual(json.loads(self.child(body).stdout), self.expected)

    def test_default_worker_scope_and_real_restarted_service_bind_packaged_bundle(self):
        body = r'''
import contextlib, io
from hepta import hia_agent_worker as worker
def invoke(arguments, request=None):
    old_in, old_out = sys.stdin, sys.stdout
    source = io.TextIOWrapper(io.BytesIO(b'' if request is None else json.dumps(request,
        sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()), encoding='utf-8')
    output = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
    sys.stdin, sys.stdout = source, output
    try:
        code = worker.main(arguments)
        output.flush()
        payload = output.buffer.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    assert code == 0, (code, payload)
    assert not [key for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')]
    assert helpers._SCOPE_OWNER is None and helpers._ACTIVE is None
    return json.loads(payload)
pins = invoke(['--installation-manifest'])
assert pins['native_helpers_sha256'] == sys.argv[3]
from hashlib import sha256
packet = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_describe',
    'arguments': {'section': 'manifest'}, 'profile_sha256': 'a' * 64,
    'catalog_sha256': pins['catalog_sha256']}
packet['request_sha256'] = sha256(json.dumps(packet, sort_keys=True,
    separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
state = str(Path(sys.argv[4]))
for _ in range(2):
    report = invoke(['--state-root', state, '--request-json-stdin'], packet)
    assert report['native_helpers_sha256'] == sys.argv[3]
    assert report['request_sha256'] == packet['request_sha256'] and report['complete'] is True
    assert report['response']['status'] == 'completed', report
print('DEFAULT_WORKER_AND_RESTARTED_SERVICE_BOUND')
'''
        run = self.child(body, self.report['default_bundle_sha256'], self.root / 'worker-state')
        self.assertEqual(run.stdout.strip(), 'DEFAULT_WORKER_AND_RESTARTED_SERVICE_BOUND')

    def test_explicit_administrator_bundle_uses_only_its_captured_images(self):
        body = r'''
import shutil
from hashlib import sha256
bundle, expected, _ = defaults.capture_default_bundle()
external = Path(sys.argv[3]); external.mkdir()
for filename in ('bundle.json', 'manifest.json'):
    shutil.copyfile(bundle.parent / filename, external / filename)
manifest = json.loads((bundle.parent / 'manifest.json').read_bytes())
shutil.copyfile(bundle.parent / manifest['image_path'], external / manifest['image_path'])
saved = bundle.read_bytes()
bundle.write_bytes(saved + b' ')
try:
    with helpers.native_helpers_scope(str(external / 'bundle.json'), expected):
        with patch('hepta.hia_json_preflight_native._load_manifest', forbidden), \
             patch.object(defaults, 'capture_default_bundle', forbidden):
            answer = owner.assess_full_cost(raw)
            assert helpers.native_helpers_identity()['native_helpers_sha256'] == expected
finally:
    bundle.write_bytes(saved)
assert not [k for k in os.environ if k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST')]
print(json.dumps(answer, sort_keys=True))
'''
        self.assertEqual(json.loads(self.child(body, self.root / 'explicit-cost-bundle').stdout), self.expected)

    def test_valid_admin_bundle_missing_cost_cannot_borrow_packaged_code(self):
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        other = self.root / 'other-bundle.json'
        payload = {'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
            'selector': 'HEPTA_HIA_PATCH_IMPACT_MANIFEST', 'manifest_path': str(self.patch_manifest),
            'manifest_sha256': sha256(self.patch_manifest.read_bytes()).hexdigest()}]}
        other.write_text(json.dumps(payload, sort_keys=True, separators=(',', ':')))
        body = r'''
with helpers.native_helpers_scope(sys.argv[3], sys.argv[4]):
    with patch.object(native.NativeFullCost, '__init__', forbidden), \
         patch('hepta.hia_json_preflight_native._load_manifest', forbidden):
        try:
            owner.assess_full_cost(raw)
        except ValueError as error:
            assert 'absent from the active worker bundle' in str(error), str(error)
        else:
            raise AssertionError('administrator bundle was supplemented from package defaults')
print('INCOMPLETE_ADMIN_BUNDLE_REFUSED')
'''
        self.assertEqual(self.child(body, other, sha256(other.read_bytes()).hexdigest()).stdout.strip(),
                         'INCOMPLETE_ADMIN_BUNDLE_REFUSED')

    def test_default_worker_rejects_ambient_selection_before_state(self):
        body = r'''
from hepta import hia_agent_worker as worker
state = Path(sys.argv[3])
os.environ[native.SELECTOR] = 'caller-may-not-select-this'
try:
    with patch('sqlite3.connect', forbidden):
        result = worker.main(['--state-root', str(state), '--request-json-stdin'])
    assert result == 2 and not state.exists()
    assert os.environ[native.SELECTOR] == 'caller-may-not-select-this'
finally:
    del os.environ[native.SELECTOR]
assert helpers._SCOPE_OWNER is None and helpers._ACTIVE is None
print('AMBIENT_SELECTION_REFUSED_BEFORE_STATE')
'''
        self.assertEqual(self.child(body, self.root / 'no-ambient-state').stdout.strip(),
                         'AMBIENT_SELECTION_REFUSED_BEFORE_STATE')

    def test_missing_and_warm_changed_package_inputs_never_fall_back(self):
        body = r'''
bundle, _digest, _pin = defaults.capture_default_bundle()
manifest = json.loads((bundle.parent / 'manifest.json').read_bytes())
paths = [bundle, bundle.parent / 'manifest.json', bundle.parent / manifest['image_path'],
         native.SOURCE, installed / 'hepta/hia_default_native_pin.py',
         next(installed.glob('hia_core-*.dist-info/RECORD'))]
data = json.loads(raw)
for path in paths:
    captured = defaults.default_image(native.SELECTOR)
    original = path.read_bytes()
    try:
        path.write_bytes(original + b' ')
        with patch.object(native.NativeFullCost, '__init__', forbidden):
            try:
                owner.assess_full_cost(raw)
            except (ValueError, OSError):
                pass
            else:
                raise AssertionError('changed package input accepted: ' + str(path))
        with patch.object(captured, '_entry', forbidden):
            try:
                captured.arm(data['arms'][0]['one_time_ns'], data['arms'][0]['observations'])
            except (ValueError, OSError):
                pass
            else:
                raise AssertionError('warm package binding ignored changed input: ' + str(path))
    finally:
        path.write_bytes(original)
for path in paths:
    held = path.with_name(path.name + '.held')
    path.rename(held)
    try:
        try:
            owner.assess_full_cost(raw)
        except (ValueError, OSError):
            pass
        else:
            raise AssertionError('missing package input silently disabled default: ' + str(path))
    finally:
        held.rename(path)
print('ALL_COLD_AND_WARM_PACKAGE_INPUTS_REFUSED')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'ALL_COLD_AND_WARM_PACKAGE_INPUTS_REFUSED')

    def test_fresh_process_cannot_downgrade_candidate_pin_to_portable_none(self):
        body = r'''
pin = installed / 'hepta/hia_default_native_pin.py'
saved = pin.read_bytes()
assert 'hepta.hia_default_native_pin' not in sys.modules
try:
    pin.write_bytes(defaults.render_pin(None))
    try:
        owner.assess_full_cost(raw)
    except ValueError as error:
        assert 'wheel RECORD' in str(error), str(error)
    else:
        raise AssertionError('rewriting the pin to portable None disabled the installed native default')
finally:
    pin.write_bytes(saved)
print('COLD_PORTABLE_DOWNGRADE_REFUSED')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'COLD_PORTABLE_DOWNGRADE_REFUSED')

    def test_repeated_defaults_release_images_immediately_with_cyclic_GC_disabled(self):
        body = r'''
import gc, weakref
observed = []
original = native.NativeFullCost.arm
def track(image, *args):
    observed.append(weakref.ref(image))
    assert image._default_package_binding.images == {}
    return original(image, *args)
enabled = gc.isenabled()
gc.disable()
try:
    with patch.object(native.NativeFullCost, 'arm', track):
        for _ in range(32):
            owner.assess_full_cost(raw)
            assert all(item() is None for item in observed), 'default mapping retained until cyclic GC'
finally:
    if enabled:
        gc.enable()
assert len(observed) == 128
print('ALL_DEFAULT_IMAGES_RELEASED_WITHOUT_CYCLIC_GC')
'''
        self.assertEqual(self.child(body).stdout.strip(), 'ALL_DEFAULT_IMAGES_RELEASED_WITHOUT_CYCLIC_GC')

    def test_concurrent_public_calls_capture_their_own_package_custody(self):
        body = r'''
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=2) as pool:
    observed = list(pool.map(lambda _: owner.assess_full_cost(raw), range(4)))
assert all(item == observed[0] for item in observed)
print(json.dumps(observed[0], sort_keys=True))
'''
        self.assertEqual(json.loads(self.child(body).stdout), self.expected)

    def test_all_original_38_callers_use_actual_installed_default(self):
        from tools.qualify_hia_default_release_callers import qualify
        result = qualify(self.root / 'build/build.json', self.root / 'original-callers')
        self.assertEqual(result['status'], 'PASS', result)
        self.assertEqual(result['actual_tests'], 38)
        self.assertEqual(result['started'], result['stopped'])
        self.assertEqual(result['planned'], result['started'])
        self.assertTrue(result['no_native_selector_environment'])
        self.assertTrue(result['source_wheel_and_installation_unchanged'])

    def test_ordinary_portable_wheel_still_has_no_default_image(self):
        base, = (self.root / 'build/base-wheel').glob('*.whl')
        portable = self.root / 'portable-installed'
        self._run(['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile', '--target', portable, base])
        script = r'''
import json, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta.hia_default_native import capture_default_bundle
from hepta.hia_full_cost_gate import assess_full_cost
assert capture_default_bundle() is None
with patch('platform.system', return_value='Darwin'), patch('platform.machine', return_value='arm64'), \
     patch('hepta.hia_native_helpers.NativeHelpersBinding', side_effect=AssertionError('native entered')):
    answer = assess_full_cost(Path(sys.argv[2]).read_bytes())
print(json.dumps(answer, sort_keys=True))
'''
        result = self._run(['-I', '-c', script, portable, self.input])
        self.assertEqual(json.loads(result.stdout), self.expected)
