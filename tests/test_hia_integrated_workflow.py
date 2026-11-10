"""Execute current Core CI shell boundaries using explicit non-native fixtures.

These are workflow failure-propagation controls, not native qualification.
Removed high-level/migration workflow test IDs are recorded as retired, not passed.
"""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/hia-core.yml'


def step(name):
    source = WORKFLOW.read_text().splitlines()
    start, = (i for i, line in enumerate(source) if line == '      - name: ' + name)
    end = next((i for i in range(start + 1, len(source)) if source[i].startswith('      - ')), len(source))
    return source[start:end]


def script(name):
    lines = step(name)
    begin = lines.index('        run: |') + 1
    end = next((i for i in range(begin, len(lines)) if lines[i] and not lines[i].startswith('          ')), len(lines))
    return '\n'.join(line[10:] for line in lines[begin:end]) + '\n'


class CoreWorkflowContractTests(unittest.TestCase):
    def test_actual_source_generator_shell_refuses_mutation_and_first_failed_generator(self):
        command = script('Regenerate actual HIA sources')
        components = command.split('for component in ', 1)[1].split('; do', 1)[0].split()
        for mode, expected in [('clean', 0), ('mutation', 1), ('failure', 7)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='hia-ci-shell-') as d:
                root = Path(d)
                (root / 'tools').mkdir()
                (root / 'marker').write_text('committed bytes')
                for i, name in enumerate(components):
                    code = ''
                    if i == 0 and mode == 'mutation':
                        code = "from pathlib import Path\nPath('marker').write_text('changed bytes')\n"
                    if i == 0 and mode == 'failure':
                        code = 'raise SystemExit(7)\n'
                    (root / ('tools/generate_hia_' + name + '.py')).write_text(code)
                def git(*args):
                    subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, timeout=10)
                git('init', '--quiet')
                for key, value in [('user.name', 'Core CI fixture'), ('user.email', 'fixture@example.invalid'),
                                   ('commit.gpgsign', 'false'), ('core.hooksPath', '/dev/null')]:
                    git('config', key, value)
                git('add', '.')
                git('commit', '--quiet', '-m', 'explicit workflow fixture')
                env = dict(os.environ, PATH=str(Path(sys.executable).parent) + ':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1')
                result = subprocess.run(['bash', '--noprofile', '--norc', '-c', command], cwd=root,
                                        env=env, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_actual_native_ci_runner_rejects_failed_skipped_and_expected_failure_outcomes(self):
        source = script('Native applications and actual Core memory controls')
        code = source.split("<<'PYTEST'\n", 1)[1].rsplit('\nPYTEST', 1)[0]
        for success, skips, expected_failures, expected in [(True, [], [], 0), (False, [], [], 1),
                                                         (True, ['fixture skip'], [], 1),
                                                         (True, [], ['fixture expected failure'], 1)]:
            with self.subTest(success=success, skips=skips, expected_failures=expected_failures):
                fixture = ('import sys,types\n'
                           'result=types.SimpleNamespace(wasSuccessful=lambda: ' + repr(success) +
                           ',skipped=' + repr(skips) + ',expectedFailures=' + repr(expected_failures) + ')\n'
                           'sys.modules["unittest"]=types.SimpleNamespace('\
                           'TextTestRunner=lambda **kwargs:types.SimpleNamespace(run=lambda suite:result),'\
                           'defaultTestLoader=types.SimpleNamespace(loadTestsFromNames=lambda names:names))\n')
                result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', fixture + code],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_actual_native_ci_retains_original_applications_and_all_core_region_controls(self):
        source = script('Native applications and actual Core memory controls')
        code = source.split("<<'PYTEST'\n", 1)[1].rsplit('\nPYTEST', 1)[0]
        node = next(n for n in ast.parse(code).body if isinstance(n, ast.Assign))
        names = ast.literal_eval(node.value)
        required = {'tests.test_hia_agent_slice_native', 'tests.test_hia_agent_stdio', 'tests.test_hia_core_json_cli', 'tests.test_hia_elf_linker',
                    'tests.test_hia_agent_identity_native', 'tests.test_hia_agent_installed_resources'}
        required.update('tests.' + p.stem for p in (ROOT / 'tests').glob('test_hia_host_region*.py'))
        self.assertEqual(set(names), required)
        self.assertEqual(len(names), len(required))

    def test_actual_failure_archive_runs_after_cold_failure_without_continuing_test_steps(self):
        lines = step('Preserve actual cold failure and stage evidence')
        self.assertIn('        if: always()', lines)
        self.assertIn('          include-hidden-files: true', lines)
        self.assertIn('          if-no-files-found: error', lines)
        source = WORKFLOW.read_text()
        self.assertNotIn('continue-on-error', source)
        self.assertIn('--output "$RUNNER_TEMP/hia-cold.json"', source)
        for path in ['hia-cold.json', 'hia-cold.cold/', 'hia-language.json', 'hia-language.assertions.json']:
            self.assertIn('            ${{ runner.temp }}/' + path, lines)
        self.assertLess(source.index('tools/replay_hia_selfhost_cold.py'),
                        source.index('      - name: Preserve actual cold failure and stage evidence'))


if __name__ == '__main__':
    unittest.main()
