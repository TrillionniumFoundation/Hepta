import importlib.util
from pathlib import Path
import sys
import tempfile
import subprocess
import json
import unittest

PATH = Path(__file__).with_name('hepta_exact_head_closure.py')
spec = importlib.util.spec_from_file_location('hepta_exact_head_closure', PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class LocalHarnessTests(unittest.TestCase):
    def test_missing_repo_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            report = module.build_report(Path(temp) / 'hepta-private-ci', None, ['native'], False, 5)
            self.assertEqual(report['source']['blockers'], ['repository-directory-unavailable'])
            self.assertFalse(report['all_blockers_closed'])
            self.assertEqual(report['authority'], 'DENY_ALL')

    def test_valid_clean_git_and_untracked_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / 'hepta-private-ci'
            repo.mkdir()
            subprocess.run(['git','init','-q',str(repo)],check=True)
            subprocess.run(['git','-C',str(repo),'config','user.email','test@example.invalid'],check=True)
            subprocess.run(['git','-C',str(repo),'config','user.name','test'],check=True)
            (repo / 'codex-rs').mkdir()
            (repo / 'codex-rs' / 'Cargo.lock').write_text('file\n')
            (repo / '.github' / 'workflows').mkdir(parents=True)
            (repo / '.github' / 'workflows' / 'blocking-ci.yml').write_text('file\n')
            subprocess.run(['git','-C',str(repo),'add','.'],check=True)
            subprocess.run(['git','-C',str(repo),'commit','-qm','test'],check=True)
            a=module.inspect_repo(repo)
            self.assertTrue(a['valid'])
            self.assertTrue(a['clean'])
            self.assertFalse(a['blockers'])
            (repo / 'untracked').write_text('dirty')
            self.assertIn('dirty-worktree', module.inspect_repo(repo)['blockers'])
            r=module.build_report(repo,a['head_sha'],['format'],True,2)
            self.assertTrue(all(x['status']=='blocked-by-source-identity' for x in r['scoped_local_checks']))

    def test_passing_child(self):
        r=module.run_bounded([sys.executable,'-c','print("ok")'],Path('/tmp'),4)
        self.assertEqual(r.status,'passed')
        self.assertEqual(r.exit_code,0)

    def test_failed_child(self):
        r=module.run_bounded([sys.executable,'-c','raise SystemExit(6)'],Path('/tmp'),4)
        self.assertEqual(r.status,'failed')
        self.assertEqual(r.exit_code,6)

    def test_output_overflow_is_fenced(self):
        r=module.run_bounded([sys.executable,'-c','print("x" * 90000)'],Path('/tmp'),4,cap=1024)
        self.assertEqual(r.status,'output-limit')
        self.assertGreater(r.bytes_seen,1024)

    def test_timeout_terminates_child(self):
        r=module.run_bounded([sys.executable,'-c','import time;time.sleep(20)'],Path('/tmp'),1)
        self.assertEqual(r.status,'timeout')
        self.assertLess(r.elapsed_seconds,5)

    def test_create_only_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            dest=Path(temp)/'receipt.json'
            module.write_create_only(dest, {'a':1})
            self.assertEqual(json.loads(dest.read_text()),{'a':1})
            with self.assertRaises(FileExistsError):
                module.write_create_only(dest, {'a':2})
            self.assertEqual(json.loads(dest.read_text()),{'a':1})

    def test_missing_executable_unavailable_not_success(self):
        r=module.run_bounded(['tool_that_does_not_exist_hepta'],Path('/tmp'),1)
        self.assertEqual(r.status,'unavailable')


    def test_post_run_source_mutation_invalidates_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / 'hepta-private-ci'
            repo.mkdir()
            subprocess.run(['git','init','-q',str(repo)],check=True)
            subprocess.run(['git','-C',str(repo),'config','user.email','test@example.invalid'],check=True)
            subprocess.run(['git','-C',str(repo),'config','user.name','test'],check=True)
            (repo / 'codex-rs').mkdir()
            (repo / 'codex-rs' / 'Cargo.lock').write_text('lock\n')
            (repo / '.github' / 'workflows').mkdir(parents=True)
            (repo / '.github' / 'workflows' / 'blocking-ci.yml').write_text('on: push\n')
            subprocess.run(['git','-C',str(repo),'add','.'],check=True)
            subprocess.run(['git','-C',str(repo),'commit','-qm','test'],check=True)
            sha = module.inspect_repo(repo)['head_sha']
            old = module.SUITES.get('mutation-test')
            module.SUITES['mutation-test'] = [
                ('mutator','.',[sys.executable,'-c', 'from pathlib import Path; Path("new-file").write_text("x")'])
            ]
            try:
                report = module.build_report(repo, sha, ['mutation-test'], True, 5)
                self.assertIn('source-or-worktree-mutated-during-checks',report['source']['blockers'])
                self.assertEqual(report['scoped_local_checks'][0]['status'],'invalidated-by-source-mutation')
            finally:
                if old is None:
                    del module.SUITES['mutation-test']
                else:
                    module.SUITES['mutation-test'] = old

    def test_no_fabricated_external_qualification(self):
        with tempfile.TemporaryDirectory() as temp:
            r=module.build_report(Path(temp) / 'hepta-private-ci', None, [], False,5)
            self.assertTrue(all(x['status']=='unverified' for x in r['external_gates']))
            self.assertFalse(r['production_qualified'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
