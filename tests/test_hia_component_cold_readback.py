"""Adversarial data readback controls; synthetic reports grant no qualification."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests import test_hia_native_cold_component as native_controls
from tools.hia_component_cold_readback import (
    AUTHORITY, CONTRACT, METADATA, native_cold_compiler, read_component_inputs,
    read_native_cold, native_cold_inputs,
)
from tools.hia_component_input_custody import capture_component_custody
from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS


ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class ComponentColdReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-cold-readback-control-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        (self.root / 'docs').mkdir()
        self.compiler = bytes.fromhex('554889e54883ec4048897dc0488975c8') + b'synthetic-not-executed'
        self.images = [self.base / ('B' + str(n) + '.flat') for n in (1, 2, 3)]
        for path in self.images:
            path.write_bytes(self.compiler)
        metadata = json.loads((ROOT / METADATA).read_bytes())
        self.paths = sorted((AUTHORITY, CONTRACT, METADATA, 'control.hepta'))
        (self.root / AUTHORITY).write_bytes(encoded({
            'schema': 'hepta.hia.native-source-authority.v1', 'paths': self.paths}))
        (self.root / METADATA).write_bytes(encoded(metadata))
        (self.root / 'control.hepta').write_bytes(b'not executed synthetic control source\n')
        self.sources = {name: sha256((self.root / name).read_bytes()).hexdigest()
                        for name in self.paths if name != CONTRACT}
        contract = deepcopy(metadata)
        contract['source_identity']['files'] = dict(self.sources)
        (self.root / CONTRACT).write_bytes(encoded(contract))
        self.sources[CONTRACT] = sha256((self.root / CONTRACT).read_bytes()).hexdigest()
        (self.root / 'author.py').write_bytes(b'# captured, not native-qualified\n')
        (self.root / 'empty.py').write_bytes(b'')
        for args in (('init', '-q'), ('add', '.'), ('-c', 'user.name=Control',
                     '-c', 'user.email=control@example.invalid', 'commit', '-qm', 'synthetic fixture')):
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)
        fixture = native_controls.NativeColdAdmissionTests()
        fixture.setUp()
        self.report = fixture.report
        self.report['source_manifest'] = self.sources
        self.report['generation_sha256'] = [sha256(self.compiler).hexdigest()] * 3
        # The independent runtime reader imports no generator. Only this test's
        # fixture author obtains the retained, separately pinned ABI reference.
        from tools.generate_hia_native_observer import reference_image
        self.report['native_flat_observer_hex'] = reference_image().hex()
        self.cold = self.base / 'cold.json'
        self.write_cold(self.report)
        self.inputs = {name: (self.root / name).read_bytes()
                       for name in ('control.hepta', 'author.py', 'empty.py')}
        cold_raw = self.cold.read_bytes()
        self.build = {'component_inputs': {name: sha256(raw).hexdigest() for name, raw in self.inputs.items()},
            'source_manifest': self.sources, 'cold_report_sha256': sha256(cold_raw).hexdigest(),
            'component_input_custody': capture_component_custody(
                self.compiler, cold_raw, self.sources, self.inputs, root=self.root)}

    def write_cold(self, value):
        self.cold.write_bytes(encoded(value))
        raw = self.cold.read_bytes()
        index = {'schema': 'hepta.hia.native-cold-generation-index.v1', 'source_head': '1' * 40,
            'location_index_only': True, 'hosted_qualification_claimed': False,
            'native_report': {'path': str(self.cold), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()},
            'generations': [{'name': 'B' + str(n), 'produced_image': str(path),
                'produced_bytes': len(self.compiler), 'produced_sha256': sha256(self.compiler).hexdigest()}
                for n, path in enumerate(self.images, 1)]}
        self.cold.with_suffix('.generations.json').write_bytes(encoded(index))

    def admit(self):
        return read_native_cold(self.root, self.cold, self.images[-1], self.compiler,
                                read=Path.read_bytes)

    def read_inputs(self, build=None, cold=True):
        return read_component_inputs(self.root, self.build if build is None else build,
            self.compiler, self.cold if cold else None, read=Path.read_bytes)

    def test_complete_control_record_keeps_native_and_git_domains_separate(self):
        self.assertEqual(self.admit(), self.sources)
        self.assertEqual(native_cold_compiler(self.root, self.cold, read=Path.read_bytes),
                         (self.images[-1], self.compiler, self.sources))
        self.assertEqual(self.read_inputs(), self.inputs)
        custody = self.build['component_input_custody']
        self.assertEqual(set(custody['native_inputs']), {'control.hepta'})
        self.assertEqual(set(custody['host_authoring_inputs']), {'author.py', 'empty.py'})
        self.assertIs(custody['host_authoring_is_native_qualified'], False)

    def test_full_cold_gate_cannot_be_replaced_by_a_location_or_partial_pass(self):
        mutations = []
        for field, value in (('nested_wall_elapsed_ns', 180_000_000_001),
                             ('returncode', False), ('status', 'COLD_SELFHOST_REPLAY_PASS')):
            changed = deepcopy(self.report)
            changed[field] = value
            mutations.append(changed)
        changed = deepcopy(self.report)
        changed['phases'].pop()
        mutations.append(changed)
        changed = deepcopy(self.report)
        changed['checks'][next(iter(changed['checks']))] = 1
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed.get('status')):
                self.write_cold(changed)
                with self.assertRaises(ValueError):
                    self.admit()

    def test_source_catalog_metadata_and_observer_are_independent_authorities(self):
        targets = (self.root / AUTHORITY, self.root / METADATA, self.root / CONTRACT,
                   self.root / 'control.hepta')
        for target in targets:
            with self.subTest(path=target.name):
                original = target.read_bytes()
                target.write_bytes(original + b' ')
                with self.assertRaises(ValueError):
                    self.admit()
                target.write_bytes(original)
        changed = deepcopy(self.report)
        changed['native_flat_observer_hex'] = bytes(1107).hex()
        self.write_cold(changed)
        with self.assertRaises(ValueError):
            self.admit()

    def test_all_three_physical_images_and_exact_b3_location_are_required(self):
        self.images[0].write_bytes(self.compiler + b'changed')
        with self.assertRaises(ValueError):
            self.admit()
        self.images[0].write_bytes(self.compiler)
        with self.assertRaises(ValueError):
            read_native_cold(self.root, self.cold, self.images[0], self.compiler, read=Path.read_bytes)

    def test_missing_forged_or_physically_changed_authoring_custody_is_refused(self):
        missing = deepcopy(self.build)
        missing.pop('component_input_custody')
        with self.assertRaises(ValueError):
            self.read_inputs(missing)
        for value in (True, 0):
            changed = deepcopy(self.build)
            changed['component_input_custody']['host_authoring_is_native_qualified'] = value
            with self.assertRaises(ValueError):
                self.read_inputs(changed)
        subprocess.run(['git', 'update-index', '--assume-unchanged', 'author.py'],
                       cwd=self.root, check=True, capture_output=True)
        (self.root / 'author.py').write_bytes(b'concealed change\n')
        with self.assertRaises(ValueError):
            self.read_inputs()

    def test_legacy_and_development_inputs_keep_their_distinct_original_requirements(self):
        legacy = {'schema': 'hepta.hia.selfhost-cold-replay.v1',
                  'source_manifest': dict(self.build['component_inputs'])}
        self.cold.write_bytes(encoded(legacy))
        build = deepcopy(self.build)
        build.pop('component_input_custody')
        build['source_manifest'] = legacy['source_manifest']
        build['cold_report_sha256'] = sha256(self.cold.read_bytes()).hexdigest()
        self.assertEqual(self.read_inputs(build), self.inputs)
        legacy['source_manifest'].pop('author.py')
        self.cold.write_bytes(encoded(legacy))
        build['source_manifest'] = legacy['source_manifest']
        build['cold_report_sha256'] = sha256(self.cold.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            self.read_inputs(build)
        build['source_manifest'] = None
        build['cold_report_sha256'] = None
        self.assertEqual(self.read_inputs(build, cold=False), self.inputs)
        build['component_input_custody'] = self.build['component_input_custody']
        with self.assertRaises(ValueError):
            self.read_inputs(build, cold=False)

    def test_symlink_and_fifo_inputs_are_refused_without_blocking_reads(self):
        path = self.root / 'author.py'
        path.unlink()
        path.symlink_to(self.root / 'control.hepta')
        with self.assertRaises(ValueError):
            self.read_inputs()
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            self.read_inputs()

    def test_independent_native_reader_imports_no_product_generator_builder_or_oracle(self):
        code = '''import importlib.abc,pathlib,sys
sys.path.insert(0,sys.argv[1])
class RefuseProduct(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=="hepta" or fullname.startswith(("hepta.","tools.build_","tools.generate_")) or "oracle" in fullname:
   raise AssertionError("forbidden independent reader import: "+fullname)
sys.meta_path.insert(0,RefuseProduct())
from tools.hia_component_cold_readback import native_cold_compiler
native_cold_compiler(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),read=pathlib.Path.read_bytes)
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
            str(ROOT), str(self.root), str(self.cold)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())


    def test_admitted_context_retains_original_report_index_and_all_generations(self):
        inputs = native_cold_inputs(self.root, self.cold, read=Path.read_bytes)
        self.assertTrue(inputs.native)
        self.assertEqual(inputs.report_bytes, self.cold.read_bytes())
        self.assertEqual(inputs.location_bytes, self.cold.with_suffix('.generations.json').read_bytes())
        self.assertEqual(inputs.source_head, '1' * 40)
        self.assertEqual(inputs.sources, self.sources)
        self.assertEqual(tuple(path for path, _ in inputs.files),
                         (self.cold, self.cold.with_suffix('.generations.json'), *self.images))
        self.assertTrue(all(raw == self.compiler for _, raw in inputs.generations))
        inputs.unchanged()
        self.images[0].write_bytes(self.compiler + b'changed after complete readback')
        with self.assertRaises(ValueError):
            inputs.unchanged()

    def test_optional_development_inputs_have_a_fixed_separate_git_whitelist(self):
        development = {name: ('# unexecuted fixed development dependency: ' + name).encode()
                       for name in NATIVE_CUSTODY_INPUTS}
        for name, raw in development.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(['git', 'add', '.'], cwd=self.root, check=True, capture_output=True)
        subprocess.run(['git', '-c', 'user.name=Control', '-c',
            'user.email=control@example.invalid', 'commit', '-qm', 'fixed development inputs'],
            cwd=self.root, check=True, capture_output=True)
        build = deepcopy(self.build)
        build['development_inputs'] = {name: sha256(raw).hexdigest()
                                       for name, raw in development.items()}
        build['component_input_custody'] = capture_component_custody(
            self.compiler, self.cold.read_bytes(), self.sources,
            {**self.inputs, **development}, root=self.root)
        self.assertEqual(self.read_inputs(build), self.inputs)
        for mutation in ('omitted-map', 'missing-input', 'arbitrary-input', 'changed-digest'):
            changed = deepcopy(build)
            if mutation == 'omitted-map':
                changed.pop('development_inputs')
            elif mutation == 'missing-input':
                changed['development_inputs'].pop(NATIVE_CUSTODY_INPUTS[0])
            elif mutation == 'arbitrary-input':
                changed['development_inputs']['author.py'] = sha256(self.inputs['author.py']).hexdigest()
            else:
                changed['development_inputs'][NATIVE_CUSTODY_INPUTS[0]] = '0' * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.read_inputs(changed)
        build.pop('component_input_custody')
        build['source_manifest'] = None
        build['cold_report_sha256'] = None
        with self.assertRaises(ValueError):
            self.read_inputs(build, cold=False)
        legacy = {'schema': 'hepta.hia.selfhost-cold-replay.v1',
                  'source_manifest': dict(build['component_inputs'])}
        self.cold.write_bytes(encoded(legacy))
        build['source_manifest'] = legacy['source_manifest']
        build['cold_report_sha256'] = sha256(self.cold.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            self.read_inputs(build)


if __name__ == '__main__':
    unittest.main()
