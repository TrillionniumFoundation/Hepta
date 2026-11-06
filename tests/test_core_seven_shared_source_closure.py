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
SYSTEM_INPUTS = plan.SYSTEM_ADDITIONS
ROUND6_COMPILER_INPUTS = ('hepta/hia_ndu_module_costs.py', 'hepta/hia_ndu_policy.py')
LINUX_COMPILER_INPUTS = ('hepta/hia_linux_kernel.py',)
SYSTEM_COMPILER_INPUTS = ('hepta/hia_system.py',)
NEW_INPUTS = (*CACHE_INPUTS, 'tests/test_core_seven_shared_source_closure.py', *VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *SYSTEM_INPUTS)
PRIOR_COMMITMENT = '36af03771b8b81803d90baafc92fd290d9e6cadbb03e7e135a99beae804bb0f0'
ROUND4_COMMITMENT = 'ffc0f4bd9585328bb21e99d0fe3bac7717b65d823a72cb5de9987886018055db'
ROUND5_COMMITMENT = 'd27b4d1edaa27950489d7b54fa6b8242b493883d0927933fa303e5b1203c9c55'
CURRENT_COMMITMENT = '0bc3fb2a0364b9358827c59f641537719521afa6820bb8a703679b8d4838fed2'


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
        self.assertEqual(len(actual), 344)
        round5 = tuple(name for name in actual if name not in (*ROUND6_INPUTS, *LINUX_INPUTS, *SYSTEM_INPUTS))
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
                                      if name not in (*VALIDATION_INPUTS, *ROUND5_VALIDATION_INPUTS, *ROUND6_INPUTS, *LINUX_INPUTS, *SYSTEM_INPUTS))
        self.assertEqual(len(before_new_controls), 261)
        self.assertEqual(plan.commitment(before_new_controls),
                         '5758e93bc7e92d4b10370593c3f20b713741b7530d977507a1430c6eb9cfb0eb')
        self.assertEqual(sum(name.startswith('hepta/') and name.count('/') == 1
                             and name.endswith('.py') for name in actual), 190)
        for name in NEW_INPUTS:
            self.assertTrue((plan.ROOT / name).is_file(), name)

    def test_each_new_compiler_module_is_required(self):
        with compiler_directory() as root, patch.object(plan, 'ROOT', root):
            for name in (*CACHE_INPUTS, *ROUND6_COMPILER_INPUTS, *LINUX_COMPILER_INPUTS, *SYSTEM_COMPILER_INPUTS):
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

    def test_duplicate_declared_filename_is_refused(self):
        changed = tuple(sorted((*plan.SOURCE_IDENTITY_PATHS, CACHE_INPUTS[0])))
        with patch.object(plan, 'SOURCE_IDENTITY_PATHS', changed):
            with self.assertRaisesRegex(ValueError, 'reviewed exact source identity closure'):
                plan.source_paths()


if __name__ == '__main__':
    unittest.main()
