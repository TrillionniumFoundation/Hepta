"""The new protocol keeps the old resource and independent-replay boundaries."""
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools import core_seven_relocation_acceptance_plan as old
from tools import core_seven_shared_acceptance_plan as p
from tools import core_seven_shared_acceptance_replay as replay


def fixture_git(root, *args, data=None):
    return subprocess.run(['git', '-C', str(root), *args], input=data,
        env={k: v for k, v in os.environ.items() if not k.startswith('GIT_')},
        capture_output=True, check=True).stdout


def fixture_commit(root, message='fixture'):
    fixture_git(root, '-c', 'user.name=HIAContract',
        '-c', 'user.email=hia@example.invalid', 'commit', '-qm', message)
    return fixture_git(root, 'rev-parse', 'HEAD').decode().strip()


@contextmanager
def source_repository():
    """Small real Git source and binary; all byte/descriptor checks stay real."""
    with tempfile.TemporaryDirectory(prefix='hia-git-source-') as directory:
        root = Path(directory)
        executable = root / 'pinned/bin/lean'
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b'fixture pinned executable\n')
        (root / 'source.rs').write_bytes(b'frozen source\n')
        (root / 'formal').mkdir()
        (root / 'formal/toolchain-lock.json').write_text(json.dumps({
            'lean_binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}))
        fixture_git(root, 'init', '-q')
        fixture_git(root, 'add', 'source.rs', 'formal/toolchain-lock.json')
        fixture_commit(root)
        paths = ('formal/toolchain-lock.json', 'source.rs')
        with ExitStack() as stack:
            stack.enter_context(patch.object(p, 'ROOT', root))
            stack.enter_context(patch.object(p.diagnostic, 'ROOT', root))
            stack.enter_context(patch.object(p, 'SOURCE_IDENTITY_PATHS', paths))
            stack.enter_context(patch.object(p, 'source_paths', return_value=paths))
            stack.enter_context(patch.object(p, 'support_paths', return_value=()))
            yield root, executable


class GitSourceProvenanceTests(unittest.TestCase):
    def test_hidden_replaced_blob_rejected_before_source_admission(self):
        with source_repository() as (root, executable):
            source = root / 'source.rs'
            frozen = source.read_bytes()
            original = fixture_git(root, 'rev-parse', 'HEAD:source.rs').decode().strip()
            admitted = p.External(executable)
            self.assertEqual(admitted.records[str(source)]['sha256'], hashlib.sha256(frozen).hexdigest())
            changed = b'unreviewed replacement\n'
            source.write_bytes(changed)
            replacement = fixture_git(root, 'hash-object', '-w', '--stdin', data=changed).decode().strip()
            fixture_git(root, 'replace', original, replacement)
            fixture_git(root, 'update-index', '--assume-unchanged', 'source.rs')
            # The untracked fixture executable is outside the source closure.
            self.assertEqual(fixture_git(root, 'status', '--porcelain=v1', '--untracked-files=no'), b'')
            self.assertEqual(fixture_git(root, 'cat-file', 'blob', original), changed)
            value = object.__new__(p.External)
            value.executable = executable
            value.paths = dict(admitted.paths)
            value.inodes, value.parents, value.records = {}, {}, {}
            with self.assertRaisesRegex(ValueError, 'canonical HEAD'):
                value.check()
            self.assertEqual((value.inodes, value.parents, value.records), ({}, {}, {}))
            self.assertFalse(hasattr(value, 'git'))
            fixture_git(root, 'replace', '-d', original)
            fixture_git(root, 'update-index', '--no-assume-unchanged', 'source.rs')
            source.write_bytes(frozen)
            self.assertEqual(p.External(executable).git, admitted.git)

    def test_inherited_repository_cannot_relabel_streamed_source(self):
        with source_repository() as (root, executable), tempfile.TemporaryDirectory(prefix='hia-other-git-') as directory:
            expected = p.diagnostic._git_baseline()
            other = Path(directory)
            fixture_git(other, 'init', '-q')
            (other / 'unrelated').write_bytes(b'other repository\n')
            fixture_git(other, 'add', 'unrelated')
            other_head = fixture_commit(other)
            self.assertNotEqual(expected['head'], other_head)
            with patch.dict(os.environ, {'GIT_DIR': str(other / '.git'),
                    'GIT_WORK_TREE': str(other), 'GIT_INDEX_FILE': str(other / '.git/index'),
                    'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.sparseCheckout',
                    'GIT_CONFIG_VALUE_0': 'true'}):
                self.assertEqual(p.diagnostic._git_baseline(), expected)
                self.assertEqual(p.External(executable).git, expected)

    def test_baseline_ignores_replacement_commit_tree(self):
        with source_repository() as (root, executable):
            expected = p.diagnostic._git_baseline()
            (root / 'source.rs').write_bytes(b'different tree\n')
            fixture_git(root, 'add', 'source.rs')
            replacement = fixture_commit(root, 'replacement tree')
            fixture_git(root, 'update-ref', 'HEAD', expected['head'])
            fixture_git(root, 'replace', expected['head'], replacement)
            self.assertNotEqual(fixture_git(root, 'rev-parse', 'HEAD^{tree}').decode().strip(), expected['tree'])
            self.assertEqual(p.diagnostic._git_baseline(), expected)

    def test_source_head_move_before_publication_is_rejected(self):
        with source_repository() as (root, executable):
            admitted = p.External(executable)
            original = p.require_canonical_git_blobs
            value = object.__new__(p.External)
            value.executable, value.paths = executable, dict(admitted.paths)
            value.inodes, value.parents, value.records = {}, {}, {}

            def move_head(*args, **kwargs):
                original(*args, **kwargs)
                fixture_git(root, '-c', 'user.name=HIAContract',
                    '-c', 'user.email=hia@example.invalid', 'commit', '--allow-empty', '-qm', 'moved HEAD')

            with patch.object(p, 'require_canonical_git_blobs', side_effect=move_head), self.assertRaisesRegex(ValueError, 'git baseline changed'):
                value.check()
            self.assertEqual((value.inodes, value.parents, value.records), ({}, {}, {}))
            self.assertFalse(hasattr(value, 'git'))


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
        self.assertEqual(len(paths), 267)
        self.assertTrue(set(old.source_paths()) < set(paths))
        for name in p.ADDITIONS:
            self.assertIn(name, paths)
            self.assertTrue((p.ROOT / name).is_file(), name)
        self.assertIn(p.shared.HELPER_PATH, paths)
        for name in ('CORE_MODEL_CONNECTION.md', 'UNSIGNED_STEP_CONNECTION.md'):
            self.assertIn('experiments/hia_initialization_frontiers_20261103/' + name, paths)


    def test_actual_compiler_hash_reads_cannot_escape_source_identity(self):
        registered = p.source_paths()
        expected = tuple(n for n in registered if n.startswith('hepta/') and
                         n.count('/') == 1 and n.endswith('.py'))
        self.assertEqual(len(expected), 186)
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
