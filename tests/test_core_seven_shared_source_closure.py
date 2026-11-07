"""Explicit cache-input closure; independent of the historical test inventories."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import core_seven_shared_acceptance_plan as plan


CACHE_INPUTS = ('hepta/hia_result_cache.py', 'hepta/hia_result_cache_audit.py')
VALIDATION_INPUTS = ('tests/test_core_capture_cleanup_replay.py', 'tests/test_core_structured_source_cost.py', 'tests/test_core_syntax_partition_parse_fast.py', 'tests/test_core_seven_external_hash.py')
ROUND5_VALIDATION_INPUTS = ('tests/test_hia_scalar_return_signature.py', 'tests/test_hia_ndu_preparation_bound.py')
ROUND6_INPUTS = plan.ROUND6_ADDITIONS
LINUX_INPUTS = plan.LINUX_ADDITIONS
ROUND6_COMPILER_INPUTS = ('hepta/hia_ndu_module_costs.py', 'hepta/hia_ndu_policy.py')
LINUX_COMPILER_INPUTS = ('hepta/hia_linux_kernel.py',)
NATIVE_AGENT_INPUTS = (
    'hepta/hia_agent_contract.py',
    'hepta/hia_agent_exec.py',
    'hepta/hia_agent_runner.py',
    'hepta/hia_agent_service.py',
    'hepta/hia_agent_store.py',
    'hepta/hia_agent_worker.py',
    'hepta/hia_machine_elf.py',
    'hepta/hia_machine_x64.py',
    'hepta/hia_program_native.py',
)
P0_P3_INPUTS = (
    'hepta/hia_agent_macro_discovery.py',
    'hepta/hia_agent_macro_policy.py',
    'hepta/hia_machine_plan.py',
    'hepta/hia_native_byte_abi.py',
    'hepta/hia_native_byte_runner.py',
)
SAFE_CORE_INPUTS = (
    'hepta/hia_safe_core.py',
    'hepta/hia_safe_core_elf.py',
    'hepta/hia_safe_core_x64.py',
)
NEW_INPUTS = (*CACHE_INPUTS, 'tests/test_core_seven_shared_source_closure.py', *VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS)
PRIOR_COMMITMENT = '36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0'
ROUND4_COMMITMENT = 'ffc0f4bd9585328bb21e99d0fe3bac7717b65d823a72cb5de9987886018055db'
ROUND5_COMMITMENT = 'd27b4d1edaa27950489d7b54fa6b8242b493883d0927933fa303e5b1203c9c55'
LINUX_COMMITMENT = 'a48ba3c0244975ebaf4219e6409a0293fa3ae7339704554dc4ba1f3e0c6eb86c'
NATIVE_AGENT_COMMITMENT = 'd999ff7dc718330771ddb745dbed6a5a7ecdcdea8f9011e35f0a07417f09b9c0'
P0_P3_COMMITMENT = '77fb9af75d987acab91d224cf47c5e6734f8c6eb9c4fa895064fba306289a016'
CURRENT_COMMITMENT = '223c03fa82d871fee3d85d57bb1e254d658a9d85007ec11bea5bfbb1fad5d1b5'


@contextmanager
def compiler_directory():
    names = tuple(name for name in plan.source_paths()
                  if name.startswith('hepta/') and name.count('/') == 1
                  and name.endswith('.py'))
    with tempfile.TemporaryDirectory(prefix='hia-explicit-compiler-closure-') as directory:
        root = Path(directory)
        (root / 'hepta').mkdir()
        for name in names:
            (root / name).write_bytes(b'')
        yield root


class FixedCompilerSourceClosureTests(unittest.TestCase):
    def test_complete_reviewed_closure_retains_every_prior_path(self):
        actual = plan.source_paths()
        self.assertEqual(len(actual), 331)
        self.assertEqual(plan.NATIVE_AGENT_ADDITIONS, NATIVE_AGENT_INPUTS)
        self.assertEqual(plan.P0_P3_ADDITIONS, P0_P3_INPUTS)
        self.assertEqual(plan.SAFE_CORE_ADDITIONS, SAFE_CORE_INPUTS)
        p0_p3 = tuple(name for name in actual if name not in SAFE_CORE_INPUTS)
        self.assertEqual(len(p0_p3), 328)
        self.assertEqual(plan.commitment(p0_p3), P0_P3_COMMITMENT)
        native_agent = tuple(name for name in p0_p3 if name not in P0_P3_INPUTS)
        self.assertEqual(len(native_agent), 323)
        self.assertEqual(plan.commitment(native_agent), NATIVE_AGENT_COMMITMENT)
        linux = tuple(name for name in native_agent if name not in NATIVE_AGENT_INPUTS)
        self.assertEqual(len(linux), 314)
        self.assertEqual(plan.commitment(linux), LINUX_COMMITMENT)
        round5 = tuple(name for name in linux if name not in (*ROUND6_INPUTS, *LINUX_INPUTS))
        self.assertEqual(len(round5), 267)
        self.assertEqual(plan.commitment(round5), ROUND5_COMMITMENT)
        round4 = tuple(name for name in round5 if name not in ROUND5_VALIDATION_INPUTS)
        self.assertEqual(len(round4), 265)
        self.assertEqual(plan.commitment(round4), ROUND4_COMMITMENT)
        self.assertEqual(plan.commitment(actual), CURRENT_COMMITMENT)
        self.assertTrue(set(NEW_INPUTS) <= set(actual))
        previous = tuple(name for name in actual if name not in NEW_INPUTS)
        self.assertEqual(len(previous), 258)
        self.assertEqual(plan.commitment(previous), PRIOR_COMMITMENT)
        before_new_controls = tuple(name for name in actual
                                      if name not in (*VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS))
        self.assertEqual(len(before_new_controls), 261)
        self.assertEqual(plan.commitment(before_new_controls),
                         '5758e93bc7e92d4b10370593c3f20b713741b7530d977507a1430c6eb9cfb0eb')
        self.assertEqual(sum(name.startswith('hepta/') and name.count('/') == 1
                             and name.endswith('.py') for name in actual), 206)
        for name in NEW_INPUTS:
            self.assertTrue((plan.ROOT / name).is_file(), name)

    def test_each_new_compiler_module_is_required(self):
        with compiler_directory() as root, patch.object(plan, 'ROOT', root):
            for name in (*CACHE_INPUTS, *ROUND6_COMPILER_INPUTS, *LINUX_COMPILER_INPUTS, *NATIVE_AGENT_INPUTS, *P0_P3_INPUTS, *SAFE_CORE_INPUTS):
                with self.subTest(name=name):
                    (root / name).unlink()
                    with self.assertRaisesRegex(ValueError, 'complete actual compiler_hash input set'):
                        plan.source_paths()
                    (root / name).write_bytes(b'')

    def test_extra_actual_compiler_filename_is_refused(self):
        with compiler_directory() as root, patch.object(plan, 'ROOT', root):
            (root / 'hepta/hia_result_cache_unreviewed.py').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'complete actual compiler_hash input set'):
                plan.source_paths()

    def test_unreviewed_declared_filename_is_refused(self):
        changed = tuple(sorted((*plan.SOURCE_IDENTITY_PATHS, 'hepta/unreviewed.py')))
        with patch.object(plan, 'SOURCE_IDENTITY_PATHS', changed):
            with self.assertRaisesRegex(ValueError, 'reviewed exact source identity closure'):
                plan.source_paths()
        # Even a reviewed current tuple cannot silently reinterpret its frozen
        # historical projection by changing which names count as additions.
        changed_additions = (*plan.P0_P3_ADDITIONS, NATIVE_AGENT_INPUTS[0])
        with patch.object(plan, 'P0_P3_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical native-Agent source identity projection'):
                plan.source_paths()
        changed_additions = (*plan.SAFE_CORE_ADDITIONS, P0_P3_INPUTS[0])
        with patch.object(plan, 'SAFE_CORE_ADDITIONS', changed_additions):
            with self.assertRaisesRegex(ValueError, 'historical P0/P3 source identity projection'):
                plan.source_paths()

    def test_duplicate_declared_filename_is_refused(self):
        changed = tuple(sorted((*plan.SOURCE_IDENTITY_PATHS, CACHE_INPUTS[0])))
        with patch.object(plan, 'SOURCE_IDENTITY_PATHS', changed):
            with self.assertRaisesRegex(ValueError, 'reviewed exact source identity closure'):
                plan.source_paths()


if __name__ == '__main__':
    unittest.main()
