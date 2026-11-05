"""Public offline package upgrade workflows on the exact component union."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock

ROOT = Path(__file__).resolve().parents[1]
BACKEND = os.environ.get('HEPTA_PACKAGE_TEST_BACKEND', 'c')


class PackageIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hepta-package-integration-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.package('math1', name='math', version='1.0.0', value=7)
        self.package('math2', name='math', version='2.0.0', value=9)
        self.app = self.package('app', kind='bin', dependencies={
            'm': self.spec(version='<2.0.0')})
        (self.app / 'src/main.hepta').write_text(
            'import m; fn main() -> i32 effects {} { return m::value(); }\n')

    def spec(self, *, version='>=1.0.0', candidates=None):
        return {'package': 'math', 'version': version,
                'candidates': candidates or ['../math1', '../math2']}

    def package(self, directory, *, name=None, version='1.0.0', kind='lib',
                value=0, dependencies=None):
        path = self.root / directory
        (path / 'src').mkdir(parents=True, exist_ok=True)
        fields = [f'[package]\nname={json.dumps(name or directory)}\n'
                  f'version={json.dumps(version)}\nkind={json.dumps(kind)}\n',
                  '[dependencies]\n']
        for alias, spec in sorted((dependencies or {}).items()):
            fields.append(alias + '={' + ', '.join(k+'='+json.dumps(v)
                          for k,v in spec.items()) + '}\n')
        (path / 'hepta.toml').write_text(''.join(fields), encoding='utf-8')
        entry = path / 'src' / ('main.hepta' if kind == 'bin' else 'lib.hepta')
        if not entry.exists():
            entry.write_text(f'pub fn value() -> i32 effects {{}} {{ return {value}; }}\n')
        return path

    def change_requirement(self, version):
        self.package('app', kind='bin', dependencies={'m': self.spec(version=version)})

    def cli(self, *args, expected=0):
        env = {**os.environ, 'PYTHONPATH': str(ROOT), 'PYTHONDONTWRITEBYTECODE': '1',
               'PYTHONIOENCODING': 'utf-8'}
        process = subprocess.run([sys.executable, '-B', '-m', 'hepta', *map(str,args)],
                                 cwd=self.root, env=env, capture_output=True,
                                 text=True, encoding='utf-8', timeout=60)
        self.assertEqual(process.returncode, expected, process.stdout + process.stderr)
        self.assertEqual(process.stderr, '')
        return json.loads(process.stdout)

    def lock(self, label):
        report = self.cli('lock', self.app)
        self.assertTrue(report['ok'])
        saved = self.root / (label + '.lock')
        shutil.copyfile(self.app / 'Hepta.lock', saved)
        self.assertEqual(json.loads(saved.read_bytes()), report['snapshot'])
        self.assertEqual(report['snapshot']['schema'], 'hepta.lock.v1')
        return saved

    def compare(self, before, after, changed):
        frozen = {p: p.read_bytes() for p in (before,after)}
        report = self.cli('lock-diff', before, after)
        self.assertTrue(report['ok'])
        self.assertEqual(report['changed'], changed)
        self.assertEqual(report['compatibility'], 'not_assessed')
        self.assertEqual(self.cli('lock-diff', before, after, '--check',
                                 expected=int(changed)), report)
        self.assertEqual({p: p.read_bytes() for p in frozen}, frozen)
        return report

    def run_locked(self, expected, app=None):
        report = self.cli('run', app or self.app, '--locked', '--backend', BACKEND,
                          '--json', expected=expected)
        self.assertEqual(report['schema'], 'hepta.run.v1')
        self.assertEqual(report['returncode'], expected)
        self.assertEqual(report['stdout'], '')
        self.assertEqual(report['stderr'], '')
        self.assertTrue(report['build']['ok'])
        print('PACKAGE_NATIVE ' + json.dumps({'backend': BACKEND, 'exit': expected,
              'toolchain': report['build']['toolchain'],
              'artifact_sha256': report['build']['artifact_sha256'],
              'source_sha256': report['build'].get('source_sha256', report['build'].get('rust_sha256')),
              'flags': report['build'].get('flags'),
              'lock_sha256': json.loads(((app or self.app)/'Hepta.lock').read_bytes())['sha256']},
              sort_keys=True), flush=True)

    def stale(self):
        with self.assertRaises(HeptaError) as caught:
            load_project(self.app, locked=True)
        self.assertEqual(caught.exception.diagnostic.code, 'E_LOCK_STALE')

    def test_public_upgrade_lock_diff_and_actual_native_selection(self):
        before = self.lock('before')
        self.run_locked(7)
        self.change_requirement('>=1.0.0')
        self.stale()
        after = self.lock('after')
        report = self.compare(before, after, True)
        self.assertEqual([x['path'] for x in report['packages']['removed']], ['../math1'])
        self.assertEqual([x['path'] for x in report['packages']['added']], ['../math2'])
        self.assertEqual(report['dependencies']['retargeted'], [
            {'package': '.', 'alias': 'm', 'before': '../math1', 'after': '../math2'}])
        self.assertEqual([x['path'] for x in report['files']['changed']], ['hepta.toml'])
        self.run_locked(9)

    def test_transitive_constraint_backtracks_and_reviews_shared_edges(self):
        self.change_requirement('>=1.0.0')
        before = self.lock('before')
        self.package('bridge', dependencies={'m': self.spec(version='<2.0.0')})
        self.package('app', kind='bin', dependencies={'m': self.spec(), 'z': {'path': '../bridge'}})
        after = self.lock('after')
        loaded = load_package(self.app)
        self.assertIs(loaded.dependencies['m'], loaded.dependencies['z'].dependencies['m'])
        report = self.compare(before, after, True)
        self.assertEqual(report['dependencies']['retargeted'], [
            {'package': '.', 'alias': 'm', 'before': '../math2', 'after': '../math1'}])
        self.assertEqual(report['dependencies']['added'], [
            {'package': '.', 'alias': 'z', 'target': '../bridge'},
            {'package': '../bridge', 'alias': 'm', 'target': '../math1'}])
        self.run_locked(7)

    def test_same_selection_requirement_change_is_manifest_only(self):
        before = self.lock('before')
        self.change_requirement('=1.0.0')
        self.stale()
        report = self.compare(before, self.lock('after'), True)
        self.assertTrue(all(not v for v in report['packages'].values()))
        self.assertTrue(all(not v for v in report['dependencies'].values()))
        self.assertEqual([x['path'] for x in report['files']['changed']], ['hepta.toml'])

    def test_unselected_source_is_outside_lock_until_new_winner(self):
        self.change_requirement('>=1.0.0')
        before = self.lock('before')
        source = self.root / 'math1/src/lib.hepta'
        source.write_text('// unselected source change\n' + source.read_text())
        self.compare(before, self.lock('still'), False)
        self.package('math1', name='math', version='3.0.0')
        self.stale()
        after = self.lock('after')
        report = self.compare(before, after, True)
        self.assertEqual(report['packages']['added'][0]['package']['version'], '3.0.0')
        self.assertEqual(report['dependencies']['retargeted'][0]['after'], '../math1')

    def test_selected_source_edit_is_visible_without_version_change(self):
        before = self.lock('before')
        source = self.root / 'math1/src/lib.hepta'
        old = source.read_bytes()
        new = old + b'// selected source change\n'
        source.write_bytes(new)
        self.stale()
        report = self.compare(before, self.lock('after'), True)
        self.assertTrue(all(not v for v in report['packages'].values()))
        self.assertTrue(all(not v for v in report['dependencies'].values()))
        self.assertEqual(report['files']['changed'], [{'path': '../math1/src/lib.hepta',
            'before': hashlib.sha256(old).hexdigest(), 'after': hashlib.sha256(new).hexdigest()}])

    def test_unsatisfied_refresh_preserves_saved_and_current_locks(self):
        before = self.lock('before')
        current = (self.app / 'Hepta.lock').read_bytes()
        self.change_requirement('>9.0.0')
        report = self.cli('lock', self.app, expected=1)
        self.assertEqual(report['diagnostics'][0]['code'], 'E_PACKAGE_RESOLUTION')
        self.assertEqual((self.app / 'Hepta.lock').read_bytes(), current)
        self.compare(before, self.app / 'Hepta.lock', False)
        self.change_requirement('>=1.0.0')
        self.compare(before, self.lock('recovered'), True)

    def test_malformed_reached_declaration_cannot_refresh_existing_lock(self):
        before = self.lock('before')
        self.package('math1', name='math', dependencies={'bad': {'git': 'https://invalid.example/repo'}})
        report = self.cli('lock', self.app, expected=1)
        self.assertEqual(report['diagnostics'][0]['code'], 'E_PACKAGE_DEPENDENCY')
        self.compare(before, self.app / 'Hepta.lock', False)

    def test_fixed_and_candidate_same_identity_keep_distinct_versions(self):
        self.package('app', kind='bin', dependencies={'m': self.spec(version='=1.0.0'),
                                                     'fixed': {'path': '../math2'}})
        before = self.lock('before')
        self.package('app', kind='bin', dependencies={'m': self.spec(version='=2.0.0'),
                                                     'fixed': {'path': '../math2'}})
        after = self.lock('after')
        report = self.compare(before, after, True)
        self.assertEqual([x['path'] for x in report['packages']['removed']], ['../math1'])
        self.assertEqual(report['packages']['added'], [])
        self.assertEqual(report['dependencies']['retargeted'], [
            {'package': '.', 'alias': 'm', 'before': '../math1', 'after': '../math2'}])
        loaded = load_package(self.app)
        self.assertIs(loaded.dependencies['m'], loaded.dependencies['fixed'])

    def test_equal_version_candidate_retarget_is_not_hidden(self):
        self.package('math2', name='math', version='1.0.0')
        before = self.lock('before')
        self.package('app', kind='bin', dependencies={'m': self.spec(candidates=['../math2'])})
        report = self.compare(before, self.lock('after'), True)
        self.assertEqual(report['packages']['removed'][0]['package']['version'], '1.0.0')
        self.assertEqual(report['packages']['added'][0]['package']['version'], '1.0.0')
        self.assertEqual(len(report['dependencies']['retargeted']), 1)

    def test_relocated_graph_retains_lock_and_actual_native_selection(self):
        before = self.lock('before')
        moved = self.root / 'relocated'
        moved.mkdir()
        for package in ('app', 'math1', 'math2'):
            shutil.copytree(self.root / package, moved / package)
        self.assertEqual(verify_lock(load_package(moved / 'app')), json.loads(before.read_bytes()))
        self.compare(before, moved / 'app/Hepta.lock', False)
        self.run_locked(7, moved / 'app')

    def test_offline_review_after_package_directories_are_removed(self):
        before = self.lock('before')
        self.change_requirement('>=1.0.0')
        after = self.lock('after')
        expected = self.compare(before, after, True)
        for package in ('app', 'math1', 'math2'):
            shutil.rmtree(self.root / package)
        self.assertEqual(self.compare(before, after, True), expected)

    def test_existing_checked_in_lock_is_byte_stable_under_resolver(self):
        target = self.root / 'legacy'
        shutil.copytree(ROOT / 'examples/packages', target)
        app = target / 'app'
        before = (app / 'Hepta.lock').read_bytes()
        verify_lock(load_package(app))
        self.assertTrue(self.cli('lock', app)['ok'])
        self.assertEqual((app / 'Hepta.lock').read_bytes(), before)
        self.compare(app / 'Hepta.lock', app / 'Hepta.lock', False)


if __name__ == '__main__':
    unittest.main()
