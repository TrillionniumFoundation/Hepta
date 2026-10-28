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
        rows = re.findall(r'^      (CARGO_HOME|CARGO_TARGET_DIR|RUSTC): (.+)$',
                          WORKFLOW.read_text(), re.MULTILINE)
        self.assertEqual(len(rows), 3)
        declared = dict(rows)
        self.assertEqual(set(declared), {'CARGO_HOME', 'CARGO_TARGET_DIR', 'RUSTC'})
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
            for name, value in declared.items():
                value = value.replace('${{ runner.temp }}', str(runner_temp))
                value = value.replace('${{ github.workspace }}', str(workspace))
                self.assertNotIn('${{', value)
                path = Path(value).resolve()
                self.assertTrue(path.is_relative_to(root))
                self.assertFalse(path.is_relative_to(workspace))
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
