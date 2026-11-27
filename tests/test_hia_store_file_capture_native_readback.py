"""Native file-capture reader controls; synthetic records grant no execution pass."""
from copy import deepcopy
from hashlib import sha256
import ast
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests import test_hia_component_cold_readback as native_controls
from tools import hia_frozen_component_sources as history
from tools import read_hia_store_file_capture_callers as reader
from tools.hia_component_input_custody import capture_component_custody

ROOT = Path(__file__).resolve().parents[1]


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class FileCaptureNativeCustodyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native_controls.ComponentColdReadbackTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.cold = self.fixture.root, self.fixture.cold
        self.evidence = self.fixture.base / 'evidence'
        self.directory = self.evidence / 'qualified'
        self.directory.mkdir(parents=True)
        builder = 'tools/build_hia_store_file_capture.py'
        files = {
            reader.SOURCE: b'synthetic source; never executed\n',
            reader.READER: b'# synthetic authoring input\n',
            builder: ("SOURCE_NAME = " + repr(reader.SOURCE) + "\nINPUTS = (SOURCE_NAME, "
                      + repr(reader.READER) + ", " + repr(builder) + ")\n").encode(),
        }
        for name, raw in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        # Extend the synthetic native authority before committing its source;
        # a .hepta input is never admitted as hosted authoring.
        self.fixture.paths = sorted((*self.fixture.paths, reader.SOURCE))
        (self.root / native_controls.AUTHORITY).write_bytes(encoded({
            'schema': 'hepta.hia.native-source-authority.v1', 'paths': self.fixture.paths}))
        sources = {name: sha256((self.root / name).read_bytes()).hexdigest()
                   for name in self.fixture.paths if name != native_controls.CONTRACT}
        contract = json.loads((self.root / native_controls.METADATA).read_bytes())
        contract['source_identity']['files'] = dict(sources)
        (self.root / native_controls.CONTRACT).write_bytes(encoded(contract))
        sources[native_controls.CONTRACT] = sha256(
            (self.root / native_controls.CONTRACT).read_bytes()).hexdigest()
        self.fixture.sources = sources
        self.fixture.report['source_manifest'] = sources
        self.fixture.write_cold(self.fixture.report)
        for args in (('add', '.'), ('-c', 'user.name=Control', '-c',
                     'user.email=control@example.invalid', 'commit', '-qm', 'synthetic component')):
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)
        self.inputs = files
        self.current = {name: sha256(raw).hexdigest() for name, raw in files.items()}
        image = b'synthetic component bytes; never executed'
        self.manifest = {
            'schema': 'hepta.hia.store-file-capture.v2',
            'image_path': 'store_file_capture.flat',
            'image_sha256': sha256(image).hexdigest(),
            'compiler_sha256': sha256(self.fixture.compiler).hexdigest(),
            'source_sha256': self.current[reader.SOURCE],
        }
        self.receipt = {
            'core_u32': len(image), 'result_u64': len(image), 'abi_status': 0,
            'input_bytes': len(files[reader.SOURCE]), 'produced_bytes': len(image),
            'status': 'returned', 'format': 'flat-x86-64', 'return_encoding': 'zero-extended-u32',
            'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
            'output_sha256': sha256(image).hexdigest(),
            'artifact_sha256': self.manifest['compiler_sha256'],
            'image_sha256': self.manifest['compiler_sha256'],
            'input_sha256': self.manifest['source_sha256'],
            'source_sha256': self.manifest['source_sha256'],
            'produced_sha256': self.manifest['image_sha256'],
            'produced_image': str(self.directory / self.manifest['image_path']),
        }
        self.build = {
            'schema': 'hepta.hia.store-file-capture-build.v2',
            'scope': 'MATCHING_SOURCE_COLD_COMPONENT',
            'source_manifest': self.fixture.sources,
            'cold_report_sha256': sha256(self.cold.read_bytes()).hexdigest(),
            'manifest': self.manifest, 'component_inputs': self.current,
            'native_compile_receipt': self.receipt,
            'component_input_custody': capture_component_custody(
                self.fixture.compiler, self.cold.read_bytes(), self.fixture.sources,
                self.inputs, root=self.root),
        }
        (self.directory / self.manifest['image_path']).write_bytes(image)
        (self.directory / 'store_file_capture.output.bin').write_bytes(image)
        (self.directory / 'manifest.json').write_bytes(encoded(self.manifest))
        self.write(self.build)

    def write(self, build):
        (self.directory / 'build.json').write_bytes(encoded(build))
        (self.directory / 'store_file_capture.receipt.json').write_bytes(
            encoded(build['native_compile_receipt']))

    def admit(self):
        captured = reader.Captures()
        result = reader.component_build(
            self.root, self.evidence, captured, self.current, self.fixture.compiler,
            sha256(self.cold.read_bytes()).hexdigest(), native_cold_path=self.cold,
            native_sources=self.fixture.sources)
        captured.unchanged()
        return result

    def test_complete_native_branch_keeps_host_and_native_domains_separate(self):
        directory, manifest = self.admit()
        self.assertEqual(directory, self.directory)
        self.assertEqual(manifest, self.manifest)
        self.assertFalse(self.build['component_input_custody']['host_authoring_is_native_qualified'])

    def test_missing_or_forged_host_custody_cannot_borrow_native_pass(self):
        variants = []
        missing = deepcopy(self.build)
        missing.pop('component_input_custody')
        variants.append(missing)
        forged = deepcopy(self.build)
        forged['component_input_custody']['host_authoring_is_native_qualified'] = True
        variants.append(forged)
        wrong = deepcopy(self.build)
        wrong['source_manifest'] = dict(self.current)
        variants.append(wrong)
        for build in variants:
            with self.subTest(build_keys=sorted(build)):
                self.write(build)
                with self.assertRaises(ValueError):
                    self.admit()

    def test_valid_rebound_custody_cannot_omit_a_declared_builder_input(self):
        changed = deepcopy(self.build)
        inputs = {name: raw for name, raw in self.inputs.items() if name != reader.READER}
        changed['component_inputs'] = {name: sha256(raw).hexdigest() for name, raw in inputs.items()}
        changed['component_input_custody'] = capture_component_custody(
            self.fixture.compiler, self.cold.read_bytes(), self.fixture.sources,
            inputs, root=self.root)
        self.write(changed)
        with self.assertRaisesRegex(ValueError, 'complete component inputs'):
            self.admit()

    def test_exact_receipt_types_survive_the_native_branch(self):
        for name, value in (('abi_status', False), ('core_u32', True),
                            ('result_u64', float(self.receipt['result_u64']))):
            with self.subTest(field=name):
                changed = deepcopy(self.build)
                changed['native_compile_receipt'][name] = value
                self.write(changed)
                with self.assertRaises(ValueError):
                    self.admit()


class FileCaptureCurrentSourceTests(unittest.TestCase):
    def test_complete_current_source_restores_all_original_callers(self):
        captures = reader.Captures()
        original, planned, sources, adjustments = reader.original_callers(ROOT, captures)
        self.assertEqual(len(planned), 112)
        self.assertEqual(len(sources), 17)
        self.assertEqual(len(original['ordinary_modules']), 9)
        self.assertEqual(adjustments, [])
        captures.unchanged()

    def test_actual_complete_reader_refuses_mixed_evaluation_root(self):
        captures = reader.Captures()
        reader.original_callers(ROOT, captures)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, raw in captures.raw.items():
                name = path.relative_to(ROOT)
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            current = {name: (root / name).read_bytes() for name in history.CURRENT}
            prior, _ = history.restore(current, root=root)
            (root / history.EVALUATION_TEST).write_bytes(prior[history.EVALUATION_TEST])
            with self.assertRaisesRegex(ValueError, 'partially reverted'):
                reader.original_callers(root, reader.Captures())

    def test_reader_imports_no_product_builder_generator_or_test_helper(self):
        tree = ast.parse((ROOT / reader.READER).read_bytes())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(value.name for value in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or '')
        self.assertFalse(any(name.startswith(('tests', 'hepta', 'tools.build_', 'tools.generate_'))
                             or 'oracle' in name for name in names), names)


if __name__ == '__main__':
    unittest.main()
