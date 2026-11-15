"""Store/shared delivery controls; complete original gates remain independent.

Unknown objects live in disposable children until actual process exit. These
controls do not infer delivery loss from exception names or clear custody.
Artifact-provider child delivery, opaque provider internals and independent
later resource close are outside this D4 scope.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_STORE_NATIVE_DELIVERY_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_STORE_NATIVE_DELIVERY_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STORE_NATIVE_DELIVERY_EVIDENCE'
ORIGINAL = ROOT / 'tests/fixtures/store_native_delivery_original_c019.json'
ORIGINAL_SHA256 = '5fccb548e4b98fd6de5ad2eb4dc88e1adac41112b1f2c850e8254d6b10853b54'
OWNERS = ('store_artifact_profile', 'service_context', 'store_lifecycle', 'cost_ledger',
          'evaluation', 'native_build_admission', 'emission', 'execution_budget',
          'candidate_budget', 'agent_journal')
NEW_INPUTS = ('hepta/hia_native_delivery.py', 'tests/test_hia_store_native_delivery.py',
              'tests/hia_store_native_delivery_cases.py',
              'tests/fixtures/store_native_delivery_original_c019.json')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def original_inventory():
    raw = ORIGINAL.read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise AssertionError('independently frozen Store delivery inventory changed')
    value = json.loads(raw)
    if (value['base_commit'] != 'c0195643083e1d4c68679237edfa77143dc7b1c6'
            or value['base_tree'] != '7a37b1ced47251fdc58e50624a5f77be56af374a'):
        raise AssertionError('original Store source identity differs')
    return value


def admit_originals():
    value = original_inventory()
    from tests.hia_store_delivery_successor import admit_composition
    composition = admit_composition(value)
    adjustments = []
    successors = []
    for name, expected in value['unchanged_files'].items():
        raw = (ROOT / name).read_bytes()
        if name in composition['source_adjustments']:
            reviewed = composition['source_adjustments'][name]
            if len(raw) != reviewed['current_bytes'] or sha256(raw).hexdigest() != reviewed['current_sha256']:
                raise AssertionError('reviewed Store successor changed: ' + name)
            successors.append(reviewed)
            continue
        if len(raw) == expected['bytes'] and sha256(raw).hexdigest() == expected['sha256']:
            continue
        from hepta.hia_native_helpers import HELPERS
        old = b'        self.assertEqual(len(HELPERS), 39)\n'
        current = ('        self.assertEqual(len(HELPERS), ' + str(len(HELPERS)) + ')\n').encode()
        restored = raw.replace(current, old, 1)
        if (name != 'tests/test_hia_worker_native_helpers.py' or len(HELPERS) < 39
                or raw.count(current) != 1 or len(restored) != expected['bytes']
                or sha256(restored).hexdigest() != expected['sha256']):
            raise AssertionError('original source, test or fixture changed: ' + name)
        adjustments.append({'path': name, 'original_sha256': expected['sha256'],
            'current_sha256': sha256(raw).hexdigest(), 'original_helper_count': 39,
            'current_helper_count': len(HELPERS),
            'sole_permitted_change': 'one exact registry-count assertion decimal literal'})
    value['registry_count_adjustments'] = adjustments
    value['successor_source_adjustments'] = successors
    value['shared_source_adjustments'] = composition['shared_adjustments']
    value['shared_dependency_review'] = composition['shared_dependency_review']
    value['adapter_source_adjustments'] = composition['adapter_source_adjustments']
    value['adapter_definition_adjustments'] = composition['adapter_definition_adjustments']
    value['original_unchanged_adapter_definitions'] = dict(value['unchanged_adapter_definitions'])
    value['unchanged_adapter_definitions'] = composition['adapter_definition_review']
    return value


def definition_pins(raw):
    module, lines = ast.parse(raw), raw.splitlines(keepends=True)
    def pin(node):
        first = min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1
        body = b''.join(lines[first:node.end_lineno])
        return {'bytes': len(body), 'sha256': sha256(body).hexdigest()}
    result = {node.name: pin(node) for node in module.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    frame = next(node for node in module.body
                 if isinstance(node, ast.ClassDef) and node.name == 'StoreArtifactProfileFrame')
    for node in frame.body:
        if isinstance(node, ast.FunctionDef) and node.name in (
                '_global', 'argument', 'effect', '_release', '_confirmed_foreign_failure'):
            result['StoreArtifactProfileFrame.' + node.name] = pin(node)
    return result


def source_pins():
    from tools.hia_selfhost_contract import file_digests
    inventory = original_inventory()
    names = set(inventory['unchanged_files']) | set(inventory['shared_dependency_review']) | set(NEW_INPUTS)
    names.update(('hepta/hia_store_artifact_profile_native.py', 'tools/build_hia_store_artifact_profile.py'))
    return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                               for name in sorted(names)}}


class StoreNativeDeliverySourceTests(unittest.TestCase):
    def test_all_original_component_callers_and_fixtures_remain_exact(self):
        value = admit_originals()
        original = value['original_caller_inventory']
        self.assertEqual(len(original['store_ordinary_and_artifact_ordered_130']), 130)
        self.assertEqual(len(original['separate_ordered_128']), 128)
        self.assertEqual(len(original['lifecycle_ordered_50']), 50)
        self.assertEqual(sum(len(ids) for ids in original['D0_D3_component_ordered_152'].values()), 152)
        self.assertEqual(len(value['D0_D3_original_component_modules']), 11)
        self.assertFalse(value['runtime_execution_before_freeze'])

    def test_original_control_graph_literal_effects_and_object_protocols_are_unchanged(self):
        value = admit_originals()
        from hepta.hia_store_artifact_profile_protocol import MODES, ARGUMENT_MODES, PORT, PORTS
        protocol = value['protocol']
        self.assertEqual(dict(MODES), protocol['modes'])
        self.assertEqual(dict(ARGUMENT_MODES), protocol['argument_modes'])
        self.assertEqual(dict(PORT), protocol['ports'])
        self.assertEqual(len(PORTS), 138)
        self.assertEqual(len(MODES) + len(ARGUMENT_MODES), 16)
        self.assertEqual(definition_pins((ROOT / 'hepta/hia_store_artifact_profile_native.py').read_bytes()),
                         value['unchanged_adapter_definitions'])
        self.assertEqual(len(value['unchanged_adapter_definitions']), 21)

    def test_shared_api_custody_and_new_controls_are_component_inputs(self):
        value = admit_originals()
        for name, expected in value['shared_dependency_review'].items():
            raw = (ROOT / name).read_bytes()
            self.assertEqual({'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}, expected, name)
        from tools.build_hia_store_artifact_profile import INPUTS
        for name in NEW_INPUTS:
            self.assertIn(name, INPUTS)
        tree = ast.parse((ROOT / 'hepta/hia_store_artifact_profile_native.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == 'ContextVar'
                             for node in ast.walk(tree)))


class StoreNativeDeliveryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching current cold or explicit development compiler')
        admit_originals()
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-store-native-delivery-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        cls.cold = cold
        cls.cold_raw = None if cold is None else Path(cold).read_bytes()
        if cold is None:
            compiler = Path(development)
        else:
            outer = json.loads(cls.cold_raw)
            cls.nested = Path(outer['nested_report'])
            cls.nested_raw = cls.nested.read_bytes()
            compiler = Path(json.loads(cls.nested_raw)['generations'][-1]['produced_image'])
        cls.compiler, cls.compiler_raw = compiler, compiler.read_bytes()
        cls.before, cls.manifests = source_pins(), {}
        for owner in OWNERS:
            directory = cls.root / ('build-' + owner)
            if owner in OWNERS[:7]:
                builder = importlib.import_module('tools.build_hia_' + owner).build
                manifest = builder(directory, compiler, cold, development=cold is None)
            elif cold is not None:
                if owner == 'agent_journal':
                    from tools.build_hia_json_preflight import build
                    manifest = build(directory, compiler, Path(cold), candidate='agent-journal')
                else:
                    manifest = importlib.import_module('tools.build_hia_' + owner).build(
                        directory, compiler, Path(cold))
            else:
                # Strict cold builders stay strict. DEV uses their unchanged
                # source/ABI with an explicitly unqualified construction record.
                from tools.qualify_hia_selfhost import compile_stage
                from tools.build_hia_source_build import _check_pack_output
                module = importlib.import_module('hepta.hia_' + owner + '_native')
                directory.mkdir(mode=0o700)
                source = module.SOURCE.read_bytes()
                label = 'agent-journal' if owner == 'agent_journal' else owner
                image, receipt = compile_stage(directory, label, compiler, source)
                raw = image.read_bytes()
                packed = _check_pack_output(receipt, (directory / (label + '.output.bin')).read_bytes(),
                                            artifact=cls.compiler_raw, source=source)
                if packed != raw or module.SOURCE.read_bytes() != source:
                    raise AssertionError('explicit DEV image output or source changed')
                value = {'schema': module.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                         'image_path': image.name, 'image_sha256': sha256(raw).hexdigest(),
                         'compiler_sha256': sha256(cls.compiler_raw).hexdigest()}
                manifest = directory / 'manifest.json'
                manifest.write_bytes(encoded(value) + b'\n')
                (directory / 'development-build.json').write_bytes(encoded({
                    'scope': 'DEVELOPMENT_COMPONENT', 'manifest': value,
                    'native_compile_receipt': receipt,
                    'matching_current_source_cold_qualified': False}) + b'\n')
            cls.manifests[owner] = str(manifest.resolve())
        cls.built = {str(path): sha256(path.read_bytes()).hexdigest()
                     for owner in OWNERS for path in sorted((cls.root / ('build-' + owner)).rglob('*'))
                     if path.is_file()}
        (cls.root / 'manifests.json').write_bytes(encoded(cls.manifests) + b'\n')

    @classmethod
    def tearDownClass(cls):
        after = source_pins()
        stable = (cls.before == after and cls.compiler.read_bytes() == cls.compiler_raw
                  and all(sha256(Path(path).read_bytes()).hexdigest() == digest
                          for path, digest in cls.built.items())
                  and (cls.cold is None or (Path(cls.cold).read_bytes() == cls.cold_raw
                                           and cls.nested.read_bytes() == cls.nested_raw)))
        record = {'schema': 'hepta.hia.store-native-delivery-custody.v1',
                  'scope': 'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
                  'matching_cold_report': cls.cold,
                  'matching_cold_sha256': None if cls.cold_raw is None else sha256(cls.cold_raw).hexdigest(),
                  'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
                  'manifests': cls.manifests, 'build_files': cls.built,
                  'source_before': cls.before, 'source_after': after,
                  'source_compiler_cold_and_build_unchanged': stable,
                  'implemented_scope': 'D4 Store active delivery with explicit D0-D3 dependencies',
                  'artifact_provider_D5_delivery_qualified': False,
                  'independent_worker_finally_close_resource_association_qualified': False,
                  'opaque_provider_internal_effects_qualified': False,
                  'test_result_owned_by_outer_runner': True,
                  'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_bytes(encoded(record) + b'\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('Store delivery source, compiler, cold or built bytes changed')

    def child(self, kind, *, timeout=120):
        directory = self.root / self._testMethodName
        directory.mkdir()
        script = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                  'from tests.hia_store_native_delivery_cases import run_child;run_child(*sys.argv[1:])')
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT), kind,
                                 str(directory), json.dumps(self.manifests)], cwd=directory,
                                env=clean_environment(), capture_output=True, timeout=timeout)
        (directory / 'stdout.log').write_bytes(result.stdout)
        (directory / 'stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0,
                         result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
        record = json.loads((directory / 'observations.json').read_bytes())
        self.assertEqual(record['status'], 'PASS')
        return record

    def test_all_seven_frame_families_bidirectional_actual_loss(self):
        self.child('frames')

    def test_literal_children_and_active_exit_cannot_swallow_or_replace_loss(self):
        self.child('cleanup')

    def test_native_init_pending_and_preentry_refusal_keep_distinct_custody(self):
        self.child('initialization')

    def test_ordinary_foreign_and_confirmed_child_keep_original_exception_identity(self):
        self.child('safe')

    def test_prepared_frames_implicit_release_thread_and_fork_ancestry(self):
        self.child('ancestry')

    def test_both_original_journals_keep_unknown_intent_and_no_replay(self):
        self.child('requests')

    def test_actual_installed_worker_store_peer_journal_bundle(self):
        self.child('installed', timeout=180)

    def test_actual_worker_process_loss_and_packaged_source_drift(self):
        self.child('installed_process', timeout=180)


if __name__ == '__main__':
    unittest.main()
