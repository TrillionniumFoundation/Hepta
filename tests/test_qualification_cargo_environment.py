"""Exercise the workflow's Cargo paths without writing build files to source."""
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


class QualificationCargoEnvironmentTests(unittest.TestCase):
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
        workflow = WORKFLOW.read_text()
        # Job-level GitHub expressions cannot use runner.temp. The two Cargo
        # paths are written by the preceding runner step to GITHUB_ENV.
        job_rows = re.findall(
            r'^      (CARGO_HOME|CARGO_TARGET_DIR|RUSTC): (.+)$',
            workflow, re.MULTILINE)
        self.assertEqual(job_rows, [
            ('RUSTC', '${{ github.workspace }}/../toolchains/rust-1.90.0/bin/rustc')])
        init_step = re.search(
            r'^      - name: Configure isolated Cargo directories\n'
            r'        shell: bash\n'
            r'        run: \|\n'
            r'((?:          [^\n]*\n)+)', workflow, re.MULTILINE)
        self.assertIsNotNone(init_step)
        self.assertLess(
            init_step.start(),
            workflow.index('      - name: Checkout frozen source snapshot'))
        script = '\n'.join(line[10:] for line in init_step.group(1).splitlines())
        self.assertNotIn('${{', script)

        with tempfile.TemporaryDirectory(prefix='hepta-cargo-workflow-') as directory:
            root = Path(directory)
            workspace, runner_temp = root / 'workspace', root / 'runner-temp'
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
            github_env = root / 'github-env'
            env.update({'RUNNER_TEMP': str(runner_temp), 'GITHUB_ENV': str(github_env)})
            initialized = subprocess.run(
                ['bash', '-euo', 'pipefail', '-c', script],
                cwd=workspace, env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            assignments = [row.split('=', 1) for row in github_env.read_text().splitlines()]
            self.assertEqual(len(assignments), 2)
            self.assertEqual({name for name, _ in assignments},
                             {'CARGO_HOME', 'CARGO_TARGET_DIR'})
            declared = dict(assignments)
            declared['RUSTC'] = job_rows[0][1].replace(
                '${{ github.workspace }}', str(workspace))
            for name, value in declared.items():
                self.assertNotIn('${{', value)
                path = Path(value).resolve()
                self.assertTrue(path.is_relative_to(root))
                self.assertFalse(path.is_relative_to(workspace))
                if name in {'CARGO_HOME', 'CARGO_TARGET_DIR'}:
                    self.assertTrue(path.is_relative_to(runner_temp))
                    self.assertTrue(path.is_dir())
                env[name] = str(path)
            # Recreate only the declared tool location as an alias to the
            # selected compiler. Its payload/sysroot is not copied or changed.
            compiler_bin = Path(env['RUSTC']).parent
            compiler_bin.parent.mkdir(parents=True)
            compiler_bin.symlink_to(Path(rustc).resolve().parent, target_is_directory=True)
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


if __name__ == '__main__':
    unittest.main()
