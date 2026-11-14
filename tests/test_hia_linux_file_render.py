"""Public type/loan/admission controls for the independent file/render profile."""
import copy
from pathlib import Path
from hashlib import sha256
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program, HIAProgramRejected, VerifiedProgram
from hepta.hia_program_runtime import execute_program
from hepta.hia_linux_file_render import (
    PROFILE, MODULE, VerifiedLinuxFileRenderProgram, _checked_components,
    PROFILE_SOURCE_FILES, COMPONENT_PINS,
)

ROOT = Path(__file__).resolve().parents[1]


class LinuxFileRenderSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / PROFILE_SOURCE_FILES[2]).read_bytes()
        cls.checked = assemble_program(cls.raw, profile=PROFILE)
        cls.document = cls.checked.as_dict()

    def test_public_roundtrip_has_separate_authority_and_default_core_refuses(self):
        self.assertIs(type(self.checked), VerifiedLinuxFileRenderProgram)
        self.assertNotIsInstance(self.checked, VerifiedProgram)
        self.assertEqual(verify_program(self.checked, profile=PROFILE).canonical_bytes,
                         self.checked.canonical_bytes)
        self.assertEqual(render_assembly(self.checked, profile=PROFILE).encode(), self.raw)
        for value in (self.document, self.checked.canonical_bytes, self.checked):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises((HIAProgramRejected, TypeError)):
                    verify_program(value)
        with self.assertRaises(HIAProgramRejected):
            assemble_program(self.raw)
        for profile in ('hepta.hia.linux-file.v1', 'hepta.hia.linux-process.v1',
                        'hepta.hia.linux-cli-process.v1', 'hepta.hia.linux-stdio.v1', 'unknown'):
            with self.subTest(profile=profile):
                with self.assertRaises(HIAProgramRejected):
                    assemble_program(self.raw, profile=profile)

    def test_resident_alias_and_wrong_mutability_reject_in_real_loan_checker(self):
        bad = copy.deepcopy(self.document)
        instruction = next(op for fn in bad['functions'] for block in fn['blocks']
                           for op in block['ops'] if op['op'] == 'linux.render.frontend')
        instruction['args'][3] = instruction['args'][0]
        with self.assertRaises(HIAProgramRejected) as exc:
            verify_program(bad, profile=PROFILE)
        self.assertIn('E_HIA_LOAN', str(exc.exception))
        bad = copy.deepcopy(self.document)
        fn = bad['functions'][0]
        fn['params'][0]['type'] = 'readbuf'
        fn['blocks'][0]['params'][0]['type'] = 'readbuf'
        with self.assertRaises(HIAProgramRejected):
            verify_program(bad, profile=PROFILE)

    def test_effect_or_instruction_relabel_cannot_admit_a_resident_call(self):
        bad = copy.deepcopy(self.document)
        for fn in bad['functions']:
            fn['effects'].remove('linux_render')
        with self.assertRaises(HIAProgramRejected):
            verify_program(bad, profile=PROFILE)
        for opcode in ('linux.render.arbitrary', 'linux.cli.control', 'linux.syscall'):
            bad = copy.deepcopy(self.document)
            instruction = next(op for fn in bad['functions'] for block in fn['blocks']
                               for op in block['ops'] if op['op'] == 'linux.render.frontend')
            instruction['op'] = opcode
            with self.subTest(opcode=opcode):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(bad, profile=PROFILE)

    def test_frozen_component_sources_reject_reorder_drift_and_mutable_bytes(self):
        components = tuple((ROOT / name).read_bytes() for name in (
            'examples/hia_bootstrap/file_render_frontend.hepta',
            'examples/hia_bootstrap/file_render_checker.hepta'))
        accepted = _checked_components(components)
        self.assertEqual(tuple(accepted), tuple(COMPONENT_PINS))
        for invalid in (components[::-1], components[:1], list(components),
                        (components[0] + b'\n', components[1]),
                        (bytearray(components[0]), components[1])):
            with self.subTest(kind=type(invalid).__name__):
                with self.assertRaises(HIAProgramRejected):
                    _checked_components(invalid)

    def test_no_implicit_provider_or_cross_profile_components_are_invoked(self):
        calls = []
        def poison(request):
            calls.append(request)
            raise AssertionError('provider must not run during failed admission')
        for profile in (None, 'hepta.hia.linux-file.v1', 'hepta.hia.linux-process.v1', 'unknown'):
            with self.subTest(profile=profile):
                with self.assertRaises(HIAProgramRejected):
                    execute_program(self.document, 'f0', (), profile=profile,
                        linux_file_provider=poison, linux_file_render_components=())
        with self.assertRaises(HIAProgramRejected):
            execute_program(self.document, 'f0', (), profile=PROFILE,
                linux_file_provider=poison, linux_process_provider=poison,
                linux_file_render_components=())
        self.assertEqual(calls, [])

    def test_public_builder_bad_pin_profile_or_component_cannot_publish_or_compile(self):
        from tools.build_hia_linux_file_render_program import build_linux_file_render_program
        components = tuple((ROOT / name).read_bytes() for name in (
            'examples/hia_bootstrap/file_render_frontend.hepta',
            'examples/hia_bootstrap/file_render_checker.hepta'))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compiler = directory / 'explicit-development-compiler.bin'
            compiler.write_bytes(b'not-an-admitted-cold-compiler')
            actual = sha256(compiler.read_bytes()).hexdigest()
            cases = ((PROFILE, '0' * 64, components),
                     ('hepta.hia.linux-file.v1', actual, components),
                     (PROFILE, actual, components[::-1]))
            with patch('tools.build_hia_linux_file_render_program.compile_stage',
                       side_effect=AssertionError('failed admission must not compile')) as compile_:
                for i, (profile, digest, values) in enumerate(cases):
                    destination = directory / str(i)
                    with self.subTest(case=i):
                        with self.assertRaises((ValueError, HIAProgramRejected)):
                            build_linux_file_render_program(self.checked, destination, profile=profile,
                                compiler=compiler, compiler_sha256=digest, components=values)
                        self.assertFalse(destination.exists())
                compile_.assert_not_called()

    def test_new_resident_pin_and_version_two_never_reuse_frozen_version_one_authority(self):
        # Retain the original method ID; the explicit successor additionally
        # refuses the complete frozen v2 authority rather than aliasing it.
        self.assertEqual(PROFILE, 'hepta.hia.linux-file-render.v3')
        for prior in ('hepta.hia.linux-file-render.v1', 'hepta.hia.linux-file-render.v2'):
            with self.subTest(prior=prior):
                with self.assertRaises(HIAProgramRejected):
                    assemble_program(self.raw, profile=prior)
        old_components = tuple((ROOT / name).read_bytes() for name in (
            'examples/hia_bootstrap/core_json_frontend.hepta',
            'examples/hia_bootstrap/selfhost.hepta'))
        with self.assertRaises(HIAProgramRejected):
            _checked_components(old_components)
        self.assertEqual(sha256(old_components[0]).hexdigest(),
                         '07aaa374f6b83fd54cc03d4578c31c558842783b2e72a0752aeafe93d8a3e532')
        self.assertEqual(sha256(old_components[1]).hexdigest(),
                         '388b182e42675f11435867dd99520e9452a4ff48e23c0766a3952b662acc7627')

    def test_profile_bounds_remain_distinct_from_old_file_and_compile_limits(self):
        from hepta import hia_linux_file as old
        from hepta import hia_linux_file_render as current
        from tools import generate_hia_selfhost_linux_file_render as compiler
        self.assertEqual((old.SOURCE_LIMIT, old.OUTPUT_LIMIT, old.WORKSPACE_LIMIT),
                         (1048576, 8388609, 1048576))
        self.assertEqual((current.FILE_BUFFER_LIMIT, current.OUTPUT_LIMIT, current.WORKSPACE_LIMIT),
                         (8388609, 1048576, 1048576))
        self.assertEqual((current.FUNCTION_LIMIT, current.BLOCK_LIMIT, current.INSTRUCTION_LIMIT),
                         (128, 1536, 8192))
        self.assertEqual(current.MODULE, MODULE)
        self.assertNotEqual(compiler.FILE_MAGIC,
                            __import__('tools.generate_hia_selfhost_linux_file', fromlist=['MAGIC']).MAGIC)

    def test_semantic_resident_retains_late_checks_and_has_no_synthetic_function(self):
        import ast
        from tools import generate_hia_file_render_checker as checker
        record = checker.projection()
        self.assertEqual(record['semantic_passes'], [
            'phase0-signatures', 'phase0-all-functions-and-resource-CFG',
            'phase1-edge-call-effect-result-checks'])
        self.assertEqual(record['symbolic_semantic_changed_functions'],
                         ['compile', 'parse_function', 'args', 'instruction', 'check_calls', 'loan_call',
                          'read_function_name', 'read_exports', 'validate_exports'])
        self.assertEqual(record['call_view_permission_rule']['only_coercion'],
                         'actual mutbuf to declared readbuf')
        self.assertTrue(record['call_view_permission_rule']['no_machine_compiler_change'])
        self.assertTrue(record['exports_presence_and_zero_item_metadata_retained'])
        self.assertTrue(record['no_synthetic_function_or_renaming'])
        self.assertEqual(record['functions'], 256)
        nodes = {node.name: node for node in ast.parse(checker.source_program()).body}
        self.assertTrue({'edge', 'instruction', 'call_results', 'loan_incoming',
                         'check_graph', 'check_calls', 'read_return_loans'} <= nodes.keys())
        self.assertTrue(all(name in record['retained_symbolic_unchanged_functions'] for name in
                            ('edge', 'call_results', 'loan_incoming',
                             'check_graph', 'read_return_loans')))
        self.assertTrue(all(name in record['symbolic_semantic_changed_functions']
                            for name in ('instruction', 'check_calls')))
        self.assertNotIn('fix_all', nodes)
        self.assertNotIn('export_wrapper', nodes)
        self.assertEqual(sha256((ROOT / checker.SOURCE).read_bytes()).hexdigest(),
                         COMPONENT_PINS['linux.render.compiler'])

    def test_256_input_inventory_preserves_author_budget_and_dead_relocation_boundary(self):
        import ast
        from tools import generate_hia_file_render_checker as checker
        from tools.generate_hia_file_render_frontend import version_inventory
        from hepta import hia_linux_file_render as current
        record = checker.projection()
        self.assertEqual(record['compiler_author_inventory_unchanged'],
                         {'functions': 128, 'blocks': 1536, 'instructions': 8192})
        self.assertEqual((current.FUNCTION_LIMIT, current.SEMANTIC_INPUT_FUNCTION_LIMIT), (128, 256))
        self.assertEqual(record['reused_phase_two_table'], {'begin': 570368, 'end': 858368,
            'only_reachable_user': ['relocation'], 'accesses_guarded_by_phase2': True})
        regions = record['workspace_layout']
        self.assertTrue(all(0 <= row['begin'] < row['end'] <= 1048576 for row in regions))
        self.assertTrue(all(left['end'] <= right['begin'] for left, right in zip(regions, regions[1:])))
        table = {row['name']: row for row in regions}
        self.assertEqual(table['functions256']['end'] - table['functions256']['begin'], 256 * 320)
        self.assertEqual(table['calls256']['end'] - table['calls256']['begin'], 256 * 256)
        self.assertEqual(table['exports256']['end'] - table['exports256']['begin'], 256 * 48)
        nodes = ast.parse(checker.source_program())
        count_calls = [call for call in ast.walk(nodes) if isinstance(call, ast.Call)
                       and isinstance(call.func, ast.Name) and len(call.args) >= 2
                       and call.func.id in {'get', 'put', 'byte', 'store', 'state_get32', 'state_put32'}
                       and isinstance(call.args[0], ast.Name) and call.args[0].id == 'w'
                       and isinstance(call.args[1], ast.Constant) and call.args[1].value == 64]
        self.assertTrue(count_calls)
        self.assertEqual({call.func.id for call in count_calls}, {'state_get32', 'state_put32'})
        versions = version_inventory()
        self.assertEqual(versions['schemas'], ['hepta.hia.program.v6', 'hepta.hia.program.v7', 'hepta.hia.program.v8'])
        self.assertEqual(versions['v7_function_return_rejections'], ['readbuf', 'mutbuf'])


if __name__ == '__main__':
    unittest.main()
