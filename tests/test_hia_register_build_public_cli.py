"""Exercise the public register scalar report across checked Core spellings and return/abort paths."""

from hashlib import sha256
import json
import os
from pathlib import Path

from hepta.elf_shared_abi import inspect_owned_shared_elf
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_verified_scalar import emit_verified_scalar
from tests.test_hia_program import arithmetic


class BuildDescriptorSourceTests(unittest.TestCase):
    def test_pinned_plan_and_prover_descriptor_domain(self):
        from hepta.hia_agent_assembly import assemble_program
        from tests.test_hia_elf_linker import reference
        from tools.generate_hia_shared_build_report import SOURCE_PATH

        root = Path(__file__).resolve().parents[1]
        program = assemble_program((root / SOURCE_PATH).read_text())
        refused = 0xfffffffd
        cases = {b'00000003': 3, b'00000009': 9, b'000abcde': 0xabcde,
                 b'7fffffff': 0x7fffffff, b'00000000': refused,
                 b'00000002': refused, b'80000000': refused, b'ffffffff': refused,
                 b'0000000F': refused, b'0000000/': refused, b'0000000:': refused,
                 b'0000000g': refused, b'0000': refused, b'000000003': refused}
        for token, expected in cases.items():
            with self.subTest(token=token):
                result, _ = reference(program, b'HIAFD001' + token, capacity=0, workspace=0)
                self.assertEqual(result, expected)


@unittest.skipUnless(os.environ.get('HIA_TEST_NATIVE_FILTER_RELEASE'), 'requires the installed native release')
class RegisterBuildReceiptTests(unittest.TestCase):
    def test_published_register_leaf_binds_both_source_forms_and_real_stack_observation(self):
        release = Path(os.environ['HIA_TEST_NATIVE_FILTER_RELEASE'])
        for op, backend, depth in [('int.add.wrap', 'auto', 0), ('int.add.checked', None, 16)]:
            with self.subTest(op=op), TemporaryDirectory() as directory:
                doc = arithmetic(op, 'u8')
                expected = emit_verified_scalar(doc)
                root = Path(directory)
                source = root / 'source.json'
                output = root / 'quoted"路径.so'
                supplied = (json.dumps(doc, indent=2, sort_keys=False) + '\n').encode()
                source.write_bytes(supplied)
                canonical = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
                argv = [release / 'hia', 'build', source, '-o', output, '--kind', 'shared']
                if backend is not None:
                    argv.extend(['--backend', backend])
                child = subprocess.run(argv, capture_output=True, env={'PATH': ''}, timeout=90)
                self.assertEqual((child.returncode, child.stderr), (0, b''), child.stdout)
                report = json.loads(child.stdout)
                self.assertEqual(report['schema'], 'hepta.hia.verified-scalar-build.v1')
                self.assertEqual(report['status'], 'smt_validated_not_executed')
                self.assertEqual((report['selected_strategy'], report['selection_refusals']), ('scalar', []))
                self.assertEqual((report['hot_stack_bytes'], report['maximum_observed_stack_bytes']), (0, depth))
                self.assertEqual((report['hot_text_bytes'], report['runtime_solver_calls'], report['wrapper_calls']),
                                 (expected.hot_text_bytes, 0, 0))
                self.assertEqual(report['object_sha256'], sha256(expected.object_bytes).hexdigest())
                self.assertEqual(report['machine_text_sha256'], sha256(expected.text_bytes).hexdigest())
                self.assertEqual(report['core_sha256'], sha256(canonical).hexdigest())
                self.assertEqual(report['output'], str(output))
                elf = output.read_bytes()
                self.assertEqual((report['artifact_bytes'], report['artifact_sha256']), (len(elf), sha256(elf).hexdigest()))
                validation = report['validation']
                self.assertEqual(validation['source_identity']['supplied_core_sha256'], sha256(supplied).hexdigest())
                self.assertEqual(validation['image_binding']['supplied_object_sha256'], report['object_sha256'])
                self.assertEqual(validation['image_binding']['final_image_sha256'], report['artifact_sha256'])
                self.assertEqual([row['result'] for row in validation['obligations']], ['sat'] + ['unsat'] * 4)
                self.assertEqual(report['toolchain']['sha256'], report['source_identity']['verified_linker_sha256'])
                self.assertTrue(validation['ok'] and validation['complete'])
                inventory = inspect_owned_shared_elf(elf, (report['export'],))
                inventory['claims']['backend_refinement_proven'] = validation['ok'] and validation['complete']
                self.assertEqual(report['binary_inventory'], inventory)
                self.assertEqual(report['machine_proof']['obligations_proven'], len(validation['obligations']))
                self.assertEqual(report['machine_proof']['profile'], report['core_profile_version'])
                self.assertEqual(report['machine_proof']['receipt_sha256'], validation['checker']['receipt_sha256'])
                self.assertFalse(report['claims']['serialized_receipt_authorizes_execution'])

    def test_rejected_source_preserves_original_driver_output_and_existing_artifact(self):
        release = Path(os.environ['HIA_TEST_NATIVE_FILTER_RELEASE'])
        examples = Path(__file__).resolve().parents[1] / 'examples/hia_safe_core'
        loan_message = 'E_HIA_SAFE_CORE: borrowed range requires an exact extent and the u32 packed-result ABI'
        forbidden_export = 'E_HIA_PROGRAM_ABI: export conflicts with the closed runtime or loader ABI'
        reserved_function = 'E_HIA_NAME: function collides with native runtime symbol'
        cases = [(name, (examples / (name + '.core.hepta')).read_bytes(), loan_message)
                 for name in ('read_byte', 'guarded_update')]
        for name, message in [('_init', forbidden_export), ('__cxa_finalize', forbidden_export),
                              ('abort', reserved_function), ('calloc', reserved_function)]:
            document = arithmetic('int.add.wrap', 'u8')
            document['functions'][0]['name'] = name
            cases.append((name, json.dumps(document).encode(), message))
        document = arithmetic('int.add.wrap', 'u8')
        document['schema'] = 'hepta.hia.program.v9'
        cases.append(('primitive-v9', json.dumps(document).encode(),
                      'E_HIA_SAFE_CORE: Safe Core admits exactly one primitive function'))
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name, source, message in cases:
                with self.subTest(name=name):
                    input_path = root / (name + '.json')
                    output_path = root / (name + '.so')
                    input_path.write_bytes(source)
                    report = {'diagnostics': [{'code': 'E_DRIVER', 'message': message, 'phase': 'driver'}],
                              'ok': False, 'status': 'error'}
                    expected = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
                    for exists in (False, True):
                        if exists:
                            output_path.write_bytes(b'original output')
                        child = subprocess.run([release / 'hia', 'build', input_path, '--kind', 'shared',
                                                '-o', output_path], env={'PATH': ''}, capture_output=True, timeout=90)
                        self.assertEqual((child.returncode, child.stdout, child.stderr), (2, expected, b''))
                        if exists:
                            self.assertEqual(output_path.read_bytes(), b'original output')
                        else:
                            self.assertFalse(output_path.exists())

    def test_existing_output_uses_the_selected_strategy_diagnostic(self):
        from tests.test_hia_verified_checked_public_cli import checked_source

        release = Path(os.environ['HIA_TEST_NATIVE_FILTER_RELEASE'])
        simd = Path(__file__).resolve().parents[1] / 'examples/hia_verified_kernels/sum_u8.hepta'
        sources = [(json.dumps(arithmetic('int.add.wrap', 'u8')).encode(),
                    'E_HIA_VERIFIED_SCALAR: output must be a new path in an existing directory'),
                   (simd.read_bytes(), 'output must be a new file in an existing directory'),
                   (checked_source('u32', 'add'),
                    'E_HIA_SAFE_CORE: output must be a new path in an existing directory')]
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (source, message) in enumerate(sources):
                source_path = root / (str(index) + '.hepta')
                source_path.write_bytes(source)
                target = root / (str(index) + '.so')
                target.symlink_to(root / 'missing-referent')
                for path in (target, root / 'missing-directory' / 'output.so'):
                    with self.subTest(index=index, path=path):
                        child = subprocess.run([release / 'hia', 'build', source_path, '--kind', 'shared',
                                                '--target-isa', 'sse2', '-o', path], env={'PATH': ''},
                                               capture_output=True, timeout=90)
                        self.assertEqual((child.returncode, child.stderr), (2, b''))
                        self.assertEqual(json.loads(child.stdout), {
                            'diagnostics': [{'code': 'E_DRIVER', 'message': message, 'phase': 'driver'}],
                            'ok': False, 'status': 'error'})
                self.assertTrue(target.is_symlink())
                self.assertFalse(target.exists())
                self.assertFalse((root / 'missing-directory').exists())

    def test_two_verified_builds_publish_one_complete_library(self):
        from concurrent.futures import ThreadPoolExecutor

        release = Path(os.environ['HIA_TEST_NATIVE_FILTER_RELEASE'])
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'kernel.so'
            sources = []
            for operation in ('int.add.wrap', 'int.sub.wrap'):
                source = root / (operation + '.hepta')
                source.write_text(json.dumps(arithmetic(operation, 'u32')))
                sources.append(source)

            def build(source):
                return subprocess.run([release / 'hia', 'build', source, '--kind', 'shared', '-o', target],
                                      env={'PATH': ''}, capture_output=True, timeout=90)

            with ThreadPoolExecutor(max_workers=2) as workers:
                published, refused = sorted(workers.map(build, sources), key=lambda result: result.returncode)
            self.assertEqual((published.returncode, refused.returncode), (0, 2))
            self.assertEqual((published.stderr, refused.stderr), (b'', b''))
            self.assertEqual(json.loads(published.stdout)['artifact_sha256'], sha256(target.read_bytes()).hexdigest())
            message = json.loads(refused.stdout)['diagnostics'][0]['message']
            self.assertIn(message, {
                'E_HIA_VERIFIED_SCALAR: output must be a new path in an existing directory',
                'E_PUBLISH_EXISTS: output must be a new file',
                'E_PUBLISH_LINK: no-replace link failed',
            })
            expected = {'diagnostics': [{'code': 'E_DRIVER', 'message': message, 'phase': 'driver'}],
                        'ok': False, 'status': 'error'}
            self.assertEqual(refused.stdout, (json.dumps(expected, indent=2, sort_keys=True) + '\n').encode())
            self.assertEqual(set(root.iterdir()), {*sources, target})
