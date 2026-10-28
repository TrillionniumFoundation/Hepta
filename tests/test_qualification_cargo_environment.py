"""Execute runner-time Cargo setup and keep its contexts at valid scopes."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import bootstrap_toolchain


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/hepta-qualification.yml'
WORKFLOWS = (WORKFLOW, ROOT / '.github/workflows/hepta-verified-optimization.yml')
SETUP_NAME = 'Configure isolated Cargo directories'
# GitHub's context-availability table excludes runner/job/env/steps here.
# https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
JOB_ENV_CONTEXTS = {'github', 'needs', 'strategy', 'matrix', 'vars', 'secrets', 'inputs'}


def job_environment(source):
    """Read the literal scalar job env in these two single-job workflows.

    This intentionally does not claim to be a general YAML/expression parser.
    Step run/with contexts are separate and may legitimately use runner.
    """
    if len(re.findall(r'(?m)^    steps:$', source)) != 1:
        raise ValueError('expected one explicit job environment and step list')
    before_steps = source.split('    steps:\n', 1)[0]
    if len(re.findall(r'(?m)^    env:$', before_steps)) != 1:
        raise ValueError('expected one explicit job environment before steps')
    body = before_steps.split('    env:\n', 1)[1]
    declared = {}
    for line in body.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'      ([A-Za-z_][A-Za-z_0-9]*): (.+)', line)
        if match is None or match[1] in declared:
            raise ValueError('unsupported or duplicate literal job environment entry')
        declared[match[1]] = match[2]
        for expression in re.findall(r'\$\{\{(.*?)\}\}', match[2]):
            contexts = re.findall(r'(?<![\w.])([A-Za-z_][A-Za-z_0-9]*)\s*(?:\.|\[)', expression)
            if set(contexts) - JOB_ENV_CONTEXTS:
                raise ValueError('context unavailable in job env: ' + expression.strip())
    return declared


def cargo_setup_script(source):
    """Extract the actual first runner step, before any compiler/install call."""
    steps = source.split('    steps:\n', 1)[1]
    first = re.split(r'(?m)^      - ', steps)[1]
    lines = first.splitlines()
    if lines[0] != 'name: ' + SETUP_NAME or '        shell: bash' not in lines:
        raise ValueError('isolated Cargo setup must be the first explicit bash step')
    if lines.count('        run: |') != 1:
        raise ValueError('expected one literal Cargo setup shell script')
    body = lines[lines.index('        run: |') + 1:]
    if any(line and not line.startswith('          ') for line in body):
        raise ValueError('invalid Cargo setup block indentation')
    script = '\n'.join(line[10:] for line in body) + '\n'
    if '${{' in script:
        raise ValueError('Cargo directory setup must use actual runner environment variables')
    return script


class QualificationCargoEnvironmentTests(unittest.TestCase):
    def test_job_env_context_scope_and_first_runner_step(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                source = workflow.read_text()
                declared = job_environment(source)
                self.assertNotIn('CARGO_HOME', declared)
                self.assertNotIn('CARGO_TARGET_DIR', declared)
                self.assertTrue(cargo_setup_script(source))
                # The previous rejected workflow is a negative control. Do not
                # make it appear valid by substituting runner.temp in a test.
                for unavailable in ('runner.temp', 'env.CARGO_HOME', 'steps.setup.outputs.path'):
                    broken = source.replace('    env:\n',
                        '    env:\n      CARGO_HOME: ${{ ' + unavailable + ' }}/cargo\n', 1)
                    with self.assertRaisesRegex(ValueError, 'unavailable in job env'):
                        job_environment(broken)
                # These existing artifact paths are at step.with scope, where
                # runner is allowed; the scope check must not ban them globally.
                self.assertIn('${{ runner.temp }}', source.split('    steps:\n', 1)[1])

    def test_bootstrap_missing_locked_cargo_rejects_before_installation(self):
        with tempfile.TemporaryDirectory(prefix='hepta-cargo-lock-') as directory:
            root = Path(directory)
            locked = json.loads((ROOT / 'toolchain-lock.json').read_text())
            (root / 'toolchain-lock.json').write_text(json.dumps([
                item for item in locked if not item['package'].startswith('cargo-')]))
            prefix = root / 'absent/toolchain'
            with patch.object(bootstrap_toolchain, 'ROOT', root), \
                    patch.object(bootstrap_toolchain.platform, 'system', return_value='Linux'), \
                    patch.object(bootstrap_toolchain.platform, 'machine', return_value='x86_64'), \
                    patch.object(sys, 'argv', ['bootstrap_toolchain.py', '--prefix', str(prefix)]), \
                    patch.object(bootstrap_toolchain.urllib.request, 'urlopen',
                                 side_effect=AssertionError('unexpected download')) as download, \
                    patch.object(bootstrap_toolchain.subprocess, 'run') as install, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as rejected:
                    bootstrap_toolchain.main()
            self.assertEqual(rejected.exception.code, 2)
            self.assertFalse(prefix.parent.exists())
            download.assert_not_called()
            install.assert_not_called()

    def test_actual_workflow_environment_keeps_cargo_build_outside_source(self):
        cargo = shutil.which('cargo')
        rustc = os.environ.get('RUSTC') or shutil.which('rustc')
        self.assertIsNotNone(cargo, 'Cargo is required for the native qualification gate')
        self.assertIsNotNone(rustc, 'rustc is required for the native qualification gate')
        version = subprocess.run([rustc, '--version'], capture_output=True, text=True, timeout=10)
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertRegex(version.stdout, r'^rustc 1\.90\.0\b')
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name), tempfile.TemporaryDirectory(prefix='hepta-cargo-workflow-') as directory:
                self.exercise_workflow(workflow, Path(directory), cargo, rustc)

    def exercise_workflow(self, workflow, root, cargo, rustc):
        source = workflow.read_text()
        declared = job_environment(source)
        script = cargo_setup_script(source)
        workspace, runner_temp = root / 'source workspace', root / 'runner temp'
        (workspace / 'src').mkdir(parents=True)
        runner_temp.mkdir()
        (workspace / 'Cargo.toml').write_text(
            '[package]\nname = "hepta-cargo-probe"\nversion = "0.0.0"\nedition = "2021"\n')
        (workspace / 'Cargo.lock').write_text(
            'version = 4\n\n[[package]]\nname = "hepta-cargo-probe"\nversion = "0.0.0"\n')
        (workspace / 'src/main.rs').write_text('fn main() { println!("7"); }\n')
        before = {str(p.relative_to(workspace)): p.read_bytes()
                  for p in workspace.rglob('*') if p.is_file()}
        env = dict(os.environ)
        environment_file = root / 'github env'
        environment_file.write_text('')
        env.update(RUNNER_TEMP=str(runner_temp), GITHUB_ENV=str(environment_file),
                   GITHUB_WORKSPACE=str(workspace))
        # Any inherited default points into source, so only the real
        # GITHUB_ENV handoff can supply the required external directories.
        env['CARGO_HOME'] = str(workspace / 'forbidden-cargo-home')
        env['CARGO_TARGET_DIR'] = str(workspace / 'forbidden-cargo-target')
        setup = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                               cwd=workspace, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(setup.returncode, 0, setup.stderr)
        rows = [line.split('=', 1) for line in environment_file.read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        exported = dict(rows)
        self.assertEqual(set(exported), {'CARGO_HOME', 'CARGO_TARGET_DIR'})
        for name, value in exported.items():
            path = Path(value).resolve()
            self.assertTrue(path.is_dir())
            self.assertTrue(path.is_relative_to(runner_temp))
            self.assertFalse(path.is_relative_to(workspace))
        # GitHub imports the environment file for subsequent steps. Execute
        # Cargo with exactly those emitted values; never replace runner.temp.
        env.update(exported)
        if 'RUSTC' in declared:
            value = declared['RUSTC'].replace('${{ github.workspace }}', str(workspace))
            self.assertNotIn('${{', value)
            self.assertIn('/rust-1.90.0/bin/rustc', value)
            compiler_bin = Path(value).parent
            compiler_bin.parent.mkdir(parents=True)
            compiler_bin.symlink_to(Path(rustc).resolve().parent, target_is_directory=True)
            env['RUSTC'] = value
        else:
            # This job obtains its already installed pinned compiler from
            # rustup in a later step; no network installer is run here.
            self.assertIn('rustup toolchain install 1.90.0 --profile minimal', source)
            self.assertIn('RUSTC=$(rustup which --toolchain 1.90.0 rustc)', source)
            env['RUSTC'] = str(Path(rustc).resolve())
        command = [cargo, 'build', '--locked', '--offline', '--manifest-path',
                   str(workspace / 'Cargo.toml')]
        built = subprocess.run(command, cwd=workspace, env=env,
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)
        metadata = subprocess.run(
            [cargo, 'metadata', '--locked', '--offline', '--no-deps',
             '--format-version', '1', '--manifest-path', str(workspace / 'Cargo.toml')],
            cwd=workspace, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(metadata.returncode, 0, metadata.stderr)
        self.assertEqual(Path(json.loads(metadata.stdout)['target_directory']).resolve(),
                         Path(env['CARGO_TARGET_DIR']).resolve())
        binary = Path(env['CARGO_TARGET_DIR']) / 'debug/hepta-cargo-probe'
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout), (0, '7\n'))
        after = {str(p.relative_to(workspace)): p.read_bytes()
                 for p in workspace.rglob('*') if p.is_file()}
        self.assertEqual(after, before)

    def test_setup_missing_runner_environment_fails_before_export(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name), tempfile.TemporaryDirectory(prefix='hepta-cargo-no-runner-') as directory:
                destination = Path(directory) / 'environment'
                destination.write_text('')
                env = dict(os.environ, GITHUB_ENV=str(destination))
                env.pop('RUNNER_TEMP', None)
                result = subprocess.run(['bash', '--noprofile', '--norc', '-c', cargo_setup_script(workflow.read_text())],
                                        cwd=directory, env=env, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(destination.read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
