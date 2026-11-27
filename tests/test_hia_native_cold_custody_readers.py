"""Native-domain custody controls, not native compilation or cold qualification.

Git and physical input reads are real. Only the complete cold gate and native
compile/pack calls are substituted so the subsequent authoring/readback domain
can be attacked independently. No fixture compiler bytes are executable.
"""
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import ast
import importlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_cli_discovery_custody as discovery
from tools import read_hia_service_bootstrap as bootstrap_reader
from tools import read_hia_store_file_capture_callers as file_reader
from tools.hia_cold_compiler import NATIVE_CUSTODY_INPUTS, read_cold_build_inputs
from tools.hia_native_cold_admission import SCHEMA
from tools.hia_native_worker_source_authority import SOURCE_SUFFIXES


BUILDERS = ('service_bootstrap', 'store_file_capture', 'store_artifact_profile',
            'store_transaction', 'service_context')
ROOT = Path(__file__).resolve().parents[1]


class NativeColdCustodyReaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-native-custody-readers-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / 'authoring'
        self.root.mkdir()
        self.builders = {name: importlib.import_module('tools.build_hia_' + name) for name in BUILDERS}
        names = set(discovery.OWNER_FILES) | set(NATIVE_CUSTODY_INPUTS)
        for builder in self.builders.values():
            names.update(builder.INPUTS)
        self.raw_inputs = {name: ('synthetic captured input; never executed: ' + name).encode()
                           for name in names}
        for name in BUILDERS:
            path = 'tools/build_hia_' + name + '.py'
            self.raw_inputs[path] = (ROOT / path).read_bytes()
        for name, raw in self.raw_inputs.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Control', '-c', 'user.email=control@example.invalid',
                 'commit', '-qm', 'Unexecuted input custody controls')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.sources = {name: sha256(raw).hexdigest() for name, raw in self.raw_inputs.items()
                        if Path(name).suffix in SOURCE_SUFFIXES}
        self.image = b'\x7fELFsynthetic compiler control; never executed'
        self.cold = self.base / 'cold.json'
        self.report = {'schema': SCHEMA, 'source_manifest': self.sources,
                       'generation_sha256': [sha256(self.image).hexdigest()] * 3}
        self.cold.write_text(json.dumps(self.report))
        rows = []
        for name in ('B1', 'B2', 'B3'):
            path = self.base / (name + '.flat')
            path.write_bytes(self.image)
            rows.append({'name': name, 'produced_image': str(path), 'produced_bytes': len(self.image),
                         'produced_sha256': sha256(self.image).hexdigest()})
        self.compiler = self.base / 'B3.flat'
        self.index = {'schema': 'hepta.hia.native-cold-generation-index.v1',
                      'source_head': self.head, 'location_index_only': True,
                      'hosted_qualification_claimed': False, 'generations': rows,
                      'native_report': {'path': str(self.cold), 'bytes': self.cold.stat().st_size,
                                        'sha256': sha256(self.cold.read_bytes()).hexdigest()}}
        self.cold.with_suffix('.generations.json').write_text(json.dumps(self.index))
        self.counter = 0

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True, stderr=subprocess.STDOUT)

    def build(self, name, *, compiler=None, legacy=False, development=False, directory=None):
        builder = self.builders[name]
        self.counter += 1
        output = self.base / ('output-' + str(self.counter)) if directory is None else directory
        cold = self.cold
        sources = self.sources
        if legacy:
            sources = {name: sha256(raw).hexdigest() for name, raw in self.raw_inputs.items()}
            cold = self.base / 'legacy.json'
            cold.write_text(json.dumps({'schema': 'hepta.hia.selfhost-cold-replay.v1',
                                        'source_manifest': sources}))
        def compile_stage(directory, label, selected_compiler, source):
            image = Path(directory) / (label + '.image.bin')
            image.write_bytes(b'unexecuted compiled-output control')
            (Path(directory) / (label + '.output.bin')).write_bytes(image.read_bytes())
            compiler_raw = Path(selected_compiler).read_bytes()
            raw = image.read_bytes()
            receipt = {'synthetic_control': True, 'status': 'returned',
                       'core_u32': len(raw), 'result_u64': len(raw), 'abi_status': 0,
                       'input_bytes': len(source), 'produced_bytes': len(raw),
                       'format': 'flat-x86-64', 'return_encoding': 'zero-extended-u32',
                       'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
                       'output_sha256': sha256(raw).hexdigest(),
                       'artifact_sha256': sha256(compiler_raw).hexdigest(),
                       'image_sha256': sha256(compiler_raw).hexdigest(),
                       'input_sha256': sha256(source).hexdigest(),
                       'source_sha256': sha256(source).hexdigest(),
                       'produced_sha256': sha256(raw).hexdigest(), 'produced_image': str(image)}
            (Path(directory) / (label + '.receipt.json')).write_text(json.dumps(receipt))
            return image, receipt
        with ExitStack() as stack:
            stack.enter_context(patch.object(builder, 'ROOT', self.root))
            stack.enter_context(patch.object(builder, 'admit_cold_build', return_value=sources))
            stack.enter_context(patch('tools.build_hia_json_preflight.admit_cold_build', return_value=sources))
            stack.enter_context(patch.object(builder, 'current_sources', return_value=sources))
            compiler_call = stack.enter_context(patch.object(builder, 'compile_stage', side_effect=compile_stage))
            manifest = builder.build(output, compiler or self.compiler,
                                     None if development else cold, development=development)
        self.assertEqual(compiler_call.call_count, 1)
        return manifest, json.loads((output / 'build.json').read_bytes())

    def admitted(self):
        with patch('tools.build_hia_json_preflight.admit_cold_build', return_value=self.sources):
            return read_cold_build_inputs(self.cold)

    def test_all_five_native_builders_bind_original_inputs_and_separate_host_dependencies(self):
        before = self.cold.read_bytes()
        for name, builder in self.builders.items():
            with self.subTest(builder=name):
                _, report = self.build(name)
                self.assertEqual(set(report['component_inputs']), set(builder.INPUTS))
                self.assertEqual(set(report['development_inputs']), set(NATIVE_CUSTODY_INPUTS))
                custody = report['component_input_custody']
                self.assertEqual(custody['source_head'], self.head)
                self.assertFalse(custody['host_authoring_is_native_qualified'])
                self.assertFalse(custody['whole_native_delivery_qualified'])
                self.assertTrue(all(Path(path).suffix in SOURCE_SUFFIXES for path in custody['native_inputs']))
                self.assertEqual(report['source_manifest'], self.sources)
        self.assertEqual(self.cold.read_bytes(), before)

    def test_other_compiler_dirty_authoring_and_foreign_campaign_fail_before_build(self):
        other = self.base / 'other.flat'
        other.write_bytes(b'different unexecuted bytes')
        for name in self.builders:
            with self.subTest(builder=name, mutation='compiler'), self.assertRaisesRegex(ValueError, 'compiler or source'):
                self.build(name, compiler=other)
            self.assertFalse((self.base / ('output-' + str(self.counter))).exists())
        host = self.root / NATIVE_CUSTODY_INPUTS[0]
        original = host.read_bytes()
        host.write_bytes(original + b' modified')
        for name in self.builders:
            with self.subTest(builder=name, mutation='dirty'), self.assertRaises(ValueError):
                self.build(name)
            self.assertFalse((self.base / ('output-' + str(self.counter))).exists())
        host.write_bytes(original)
        self.index['source_head'] = '0' * 40
        self.cold.with_suffix('.generations.json').write_text(json.dumps(self.index))
        for name in self.builders:
            with self.subTest(builder=name, mutation='head'), self.assertRaisesRegex(ValueError, 'commit differs'):
                self.build(name)
            self.assertFalse((self.base / ('output-' + str(self.counter))).exists())

    def test_original_hosted_and_explicit_development_builds_keep_their_input_domains(self):
        for name, builder in self.builders.items():
            for mode in ('legacy', 'development'):
                with self.subTest(builder=name, mode=mode):
                    _, report = self.build(name, **{mode: True})
                    self.assertNotIn('component_input_custody', report)
                    self.assertNotIn('development_inputs', report)
                    self.assertEqual(set(report['component_inputs']), set(builder.INPUTS))

    def test_bootstrap_reader_rederives_four_fixed_component_whitelists_and_custody(self):
        inputs = self.admitted()
        with patch.object(bootstrap_reader, 'ROOT', self.root):
            for name in ('service_bootstrap', 'store_artifact_profile', 'store_transaction', 'service_context'):
                _, report = self.build(name)
                bootstrap_reader.native_component_custody(report, inputs, [])
                for mutation in ('omission', 'extra', 'scope', 'dependency', 'native-as-host'):
                    bad = deepcopy(report)
                    if mutation == 'omission':
                        bad['component_inputs'].pop(self.builders[name].INPUTS[0])
                    elif mutation == 'extra':
                        bad['component_inputs']['tools/arbitrary.py'] = '0' * 64
                    elif mutation == 'scope':
                        bad['component_input_custody']['host_authoring_is_native_qualified'] = True
                    elif mutation == 'dependency':
                        bad['development_inputs'].clear()
                    else:
                        custody = bad['component_input_custody']
                        key = next(iter(custody['native_inputs']))
                        custody['host_authoring_inputs'][key] = custody['native_inputs'].pop(key)
                    with self.subTest(builder=name, mutation=mutation), self.assertRaises(ValueError):
                        bootstrap_reader.native_component_custody(bad, inputs, [])

    def test_discovery_retains_original_report_and_cannot_relabel_host_or_omit_binding(self):
        with patch.object(discovery, 'ROOT', self.root), \
                patch('tools.build_hia_json_preflight.admit_cold_build', return_value=self.sources):
            authority = discovery.admit_cold(self.cold)
            discovery.guard_authority(authority)
            self.assertEqual(authority['source_manifest'], self.sources)
            self.assertEqual(len(authority['input_bindings']),
                             len(set(discovery.OWNER_FILES) | set(NATIVE_CUSTODY_INPUTS)) + 5)
            for mutation in ('binding', 'source', 'host-scope', 'commit'):
                bad = deepcopy(authority)
                if mutation == 'binding':
                    bad['input_bindings'].pop()
                elif mutation == 'source':
                    bad['source_manifest']['tools/hia_cli_discovery_custody.py'] = '1' * 64
                elif mutation == 'host-scope':
                    bad['component_input_custody']['host_authoring_is_native_qualified'] = True
                else:
                    bad['component_input_custody']['source_head'] = '0' * 40
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    discovery.guard_authority(bad)
        self.assertEqual(json.loads(self.cold.read_bytes()), self.report)

    def test_file_capture_reader_preserves_physical_native_files_and_rejects_source_substitution(self):
        with patch('tools.hia_component_cold_readback.read_native_cold', return_value=self.sources):
            captured = file_reader.Captures()
            compiler, digest = file_reader.cold_build(self.cold, captured, self.sources, repository=self.root)
            self.assertEqual(compiler, self.image)
            self.assertEqual(digest, sha256(self.cold.read_bytes()).hexdigest())
            self.assertEqual(set(captured.raw), {self.cold, self.cold.with_suffix('.generations.json'),
                *(self.base / (name + '.flat') for name in ('B1', 'B2', 'B3'))})
            with self.assertRaisesRegex(ValueError, 'current readback'):
                file_reader.cold_build(self.cold, file_reader.Captures(), {}, repository=self.root)

    def test_file_capture_component_reader_keeps_pack_controls_and_separate_input_custody(self):
        evidence = self.base / 'file-capture-evidence'
        evidence.mkdir()
        manifest, report = self.build('store_file_capture', directory=evidence / 'qualified')
        build_path = manifest.parent / 'build.json'
        with patch('tools.hia_component_cold_readback.read_native_cold', return_value=self.sources):
            def read():
                return file_reader.component_build(self.root, evidence, file_reader.Captures(),
                    {name: sha256(raw).hexdigest() for name, raw in self.raw_inputs.items()},
                    self.image, sha256(self.cold.read_bytes()).hexdigest(),
                    native_cold_path=self.cold, native_sources=self.sources)
            self.assertEqual(read(), (manifest.parent, report['manifest']))
            for mutation in ('input', 'dependency', 'scope', 'pack-status'):
                bad = deepcopy(report)
                if mutation == 'input':
                    bad['component_inputs'].pop(self.builders['store_file_capture'].INPUTS[0])
                elif mutation == 'dependency':
                    bad['development_inputs'][NATIVE_CUSTODY_INPUTS[0]] = '0' * 64
                elif mutation == 'scope':
                    bad['component_input_custody']['whole_native_delivery_qualified'] = True
                else:
                    bad['native_compile_receipt']['abi_status'] = 1
                    (manifest.parent / 'store_file_capture.receipt.json').write_text(
                        json.dumps(bad['native_compile_receipt']))
                build_path.write_text(json.dumps(bad))
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    read()
                build_path.write_text(json.dumps(report))


    def test_source_suite_keeps_original_methods_and_both_explicit_supplements(self):
        directory = self.base / 'source-suite'
        directory.mkdir()
        originals = {}
        expected = []
        for selector in bootstrap_reader.SELECTIONS['source']:
            module, classname = selector.rsplit('.', 1)
            path = directory / (module.replace('.', '/') + '.py')
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = (ROOT / path.relative_to(directory)).read_bytes()
            path.write_bytes(raw)
            originals[path] = (raw, classname)
            node = next(n for n in ast.parse(raw).body
                        if isinstance(n, ast.ClassDef) and n.name == classname)
            expected.extend(selector + '.' + name for name in sorted(
                n.name for n in node.body if isinstance(n, ast.FunctionDef)
                and n.name.startswith('test_')))
        self.assertEqual(len(expected), 8)
        with patch.object(bootstrap_reader, 'ROOT', directory):
            captured = []
            self.assertEqual(bootstrap_reader.method_ids('source', captured), expected)
            self.assertEqual({path for path, _ in captured}, set(originals))
            for path, (raw, classname) in originals.items():
                original_tree = ast.parse(raw)
                node = next(n for n in original_tree.body
                            if isinstance(n, ast.ClassDef) and n.name == classname)
                methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)
                           and n.name.startswith('test_')]
                cases = [('omission', name) for name in methods]
                cases += [('replacement', methods[0]), ('extra', methods[0]),
                          ('duplicate_replaces_another', methods[0])]
                for mutation, target in cases:
                    tree = ast.parse(raw)
                    node = next(n for n in tree.body
                                if isinstance(n, ast.ClassDef) and n.name == classname)
                    method = next(n for n in node.body
                                  if isinstance(n, ast.FunctionDef) and n.name == target)
                    if mutation == 'omission':
                        node.body.remove(method)
                    elif mutation == 'replacement':
                        method.name = 'test_unreviewed_replacement'
                    elif mutation == 'extra':
                        node.body.append(ast.parse(
                            'def test_unreviewed_extra(self): pass').body[0])
                    else:
                        other = next(n for n in node.body if isinstance(n, ast.FunctionDef)
                                     and n.name.startswith('test_') and n.name != target)
                        node.body.remove(other)
                        node.body.append(deepcopy(method))
                    path.write_text(ast.unparse(tree) + '\n')
                    with self.subTest(module=path.name, mutation=mutation, target=target), \
                            self.assertRaises(ValueError):
                        bootstrap_reader.method_ids('source', [])
                    path.write_bytes(raw)
            self.assertEqual(bootstrap_reader.method_ids('source', []), expected)


if __name__ == '__main__':
    unittest.main()
