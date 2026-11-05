"""The new protocol keeps the old resource and independent-replay boundaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools import core_seven_relocation_acceptance_plan as old
from tools import core_seven_shared_acceptance_plan as p
from tools import core_seven_shared_acceptance_replay as replay


class SharedAcceptanceContractTests(unittest.TestCase):
    def test_every_existing_hard_budget_unchanged(self):
        self.assertEqual(p.BUDGETS, old.BUDGETS)
        self.assertEqual(p.RAW_GLOBAL, old.RAW_GLOBAL)
        self.assertEqual(p.METADATA_RESERVE, old.METADATA_RESERVE)
        self.assertEqual(p.support_paths(), old.support_paths())
        self.assertEqual(len(p.FROZEN_FILES), 81)
        self.assertEqual(len(p.SOURCE_FILES), 22)
        self.assertEqual(len(p.MODULE_FILES), 11)
        self.assertEqual(p.cap('IDENTITY.json'), old.cap('IDENTITY.json'))

    def test_source_identity_includes_every_new_trust_dependency(self):
        paths = p.source_paths()
        self.assertEqual(len(paths), 259)
        self.assertTrue(set(old.source_paths()) < set(paths))
        for name in p.ADDITIONS:
            self.assertIn(name, paths)
            self.assertTrue((p.ROOT / name).is_file(), name)
        self.assertIn(p.shared.HELPER_PATH, paths)
        for name in ('CORE_MODEL_CONNECTION.md', 'UNSIGNED_STEP_CONNECTION.md'):
            self.assertIn('experiments/hia_initialization_frontiers_20261103/' + name, paths)


    def test_foreign_buffer_abi_is_bound_to_full_compiler_source_identity(self):
        # Any new hepta/*.py byte is read by pipeline.compiler_hash.
        # The frozen proof source set must refuse unregistered compiler input.
        name = 'hepta/hia_foreign_buffer_abi.py'
        self.assertTrue((p.ROOT / name).is_file())
        self.assertIn(name, p.ADDITIONS)
        self.assertIn(name, p.source_paths())

    def test_actual_compiler_hash_reads_cannot_escape_source_identity(self):
        registered = p.source_paths()
        expected = tuple(n for n in registered if n.startswith('hepta/') and
                         n.count('/') == 1 and n.endswith('.py'))
        self.assertEqual(len(expected), 185)
        self.assertEqual(expected, tuple(sorted(x.relative_to(p.ROOT).as_posix()
                         for x in (p.ROOT / 'hepta').glob('*.py'))))
        with tempfile.TemporaryDirectory(prefix='hia-compiler-inputs-') as directory:
            root = Path(directory)
            (root / 'hepta').mkdir()
            for name in expected:
                (root / name).write_bytes(b'')
            with patch.object(p, 'ROOT', root):
                self.assertEqual(p.source_paths(), registered)
                unbound = root / 'hepta' / 'unbound_compiler_input.py'
                unbound.write_text('UNREGISTERED = True\n')
                with self.assertRaisesRegex(ValueError, 'compiler_hash input set'):
                    p.source_paths()
                unbound.unlink()
                (root / expected[0]).unlink()
                with self.assertRaisesRegex(ValueError, 'compiler_hash input set'):
                    p.source_paths()

    def test_success_flag_cannot_replace_complete_replay(self):
        with tempfile.TemporaryDirectory(prefix='hia-shared-') as directory:
            Path(directory, 'RESULT.json').write_text(json.dumps({
                'status': 'passed', 'kernel_core_syntax_connection_checked': True}))
            with self.assertRaises(ValueError):
                replay.verify_evidence(directory)

    def test_source_generation_never_grants_broader_authority(self):
        for checked in (False, True):
            flags = p.flags(checked)
            self.assertFalse(flags['actual_core_bridge_proved'])
            self.assertFalse(flags['python_exporter_refinement_proved'])
            self.assertTrue(all(x['status'] == 'unproved' for x in flags['obligations']))
            self.assertEqual(flags['authority']['authority'], 'DENY_ALL')
            self.assertFalse(flags['authority']['production_admission'])

    def test_timeouts_and_unobserved_cleanup_still_fail(self):
        process = dict(spawned=True, returncode=0, timed_out=False, incomplete=False,
            output_truncated=False, leader_reaped=True, stdout_eof=True, stderr_eof=True,
            original_group_empty=True, elapsed_ns=1, cleanup_ns=1, leader_pid=123,
            original_pgid=123, leader_start_ticks=1, terminal_observation='waitid_wnowait',
            pre_reap_group_signal='sigkill_sent', leader_reap_observed=True,
            post_reap_group_probe='esrch')
        p.validate_process(process, success=True)
        for changed in ({'elapsed_ns': 60000000000}, {'cleanup_ns': 2000000000},
                        {'leader_reap_observed': False}, {'stdout_eof': False},
                        {'original_group_empty': False}, {'timed_out': True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                p.validate_process({**process, **changed}, success=True)


if __name__ == '__main__':
    unittest.main()
