"""Exercise public builder scripts outside the checkout import environment."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/build_hia_source_build.py'
BUILDER_SCRIPTS = (
    'build_hia_agent_binary64.py',
    'build_hia_agent_binary64_format.py',
    'build_hia_agent_data_json.py',
    'build_hia_agent_identity.py',
    'build_hia_agent_slice.py',
    'build_hia_agent_snapshot.py',
    'build_hia_agent_snapshot_json.py',
    'build_hia_agent_stdio.py',
    'build_hia_artifact_publication.py',
    'build_hia_capability_renaming.py',
    'build_hia_composite_constructor.py',
    'build_hia_composite_functions.py',
    'build_hia_composite_outer.py',
    'build_hia_core_admission.py',
    'build_hia_core_admission_cli.py',
    'build_hia_core_json_cli.py',
    'build_hia_core_json_frontend.py',
    'build_hia_core_module_graph.py',
    'build_hia_core_patch_cli.py',
    'build_hia_core_patch_result_cli.py',
    'build_hia_core_workspace_cli.py',
    'build_hia_core_workspace_facts.py',
    'build_hia_core_workspace_json.py',
    'build_hia_core_workspace_json_cli.py',
    'build_hia_core_workspace_pipeline.py',
    'build_hia_elf_linker.py',
    'build_hia_execution_budget.py',
    'build_hia_function_shape.py',
    'build_hia_instruction_policy.py',
    'build_hia_json_canonical.py',
    'build_hia_json_decode.py',
    'build_hia_json_preflight.py',
    'build_hia_ndu_bridge.py',
    'build_hia_ndu_dynamic_bridge.py',
    'build_hia_ndu_value_bridge.py',
    'build_hia_nominal_json.py',
    'build_hia_program_shape.py',
    'build_hia_raw_model_bridge.py',
    'build_hia_recursive_ndu_bridge.py',
    'build_hia_release_install.py',
    'build_hia_release_selection.py',
    'build_hia_safe_core.py',
    'build_hia_sha256.py',
    'build_hia_source_build.py',
)


class SourceBuilderEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-source-build-entry-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environment = dict(os.environ)
        self.environment.pop('PYTHONPATH', None)
        self.environment.pop('PYTHONHOME', None)

    def invoke(self, *arguments, script=SCRIPT):
        # -I also excludes the working directory and user site packages. The
        # script must locate its own checkout before importing tools or hepta.
        return subprocess.run(
            [sys.executable, '-I', '-B', str(script), *map(str, arguments)],
            cwd=self.directory, env=self.environment, capture_output=True,
            text=True, timeout=30,
        )

    def test_public_builder_help_from_unrelated_directory_without_pythonpath(self):
        for name in BUILDER_SCRIPTS:
            with self.subTest(script=name):
                result = self.invoke('--help', script=ROOT / 'tools' / name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, '')
                self.assertIn('usage:', result.stdout)
                self.assertIn('--help', result.stdout)
                self.assertIn('--output', result.stdout)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_invalid_cold_report_is_refused_before_output_creation(self):
        compiler = self.directory / 'compiler.bin'
        compiler.write_bytes(b'not executable')
        cold = self.directory / 'invalid-cold.json'
        cold.write_text('{}')
        output = self.directory / 'output'
        result = self.invoke('--compiler', compiler, '--cold-report', cold,
                             '--output', output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('completed matching native cold qualification is required', result.stderr)
        self.assertNotIn('ModuleNotFoundError', result.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(compiler.read_bytes(), b'not executable')
        self.assertEqual(cold.read_text(), '{}')

    def test_missing_cold_report_is_refused_before_output_creation(self):
        compiler = self.directory / 'compiler.bin'
        compiler.write_bytes(b'not executable')
        cold = self.directory / 'absent-cold.json'
        output = self.directory / 'output'
        result = self.invoke('--compiler', compiler, '--cold-report', cold,
                             '--output', output)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FileNotFoundError', result.stderr)
        self.assertIn(str(cold), result.stderr)
        self.assertNotIn('ModuleNotFoundError', result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(cold.exists())
        self.assertEqual(compiler.read_bytes(), b'not executable')

    def test_lazy_identity_builder_import_reaches_its_real_input_boundary(self):
        # Its --help can succeed without importing tools. This real invocation
        # detects a missing direct-entry import path after argparse returns.
        compiler = self.directory / 'compiler.bin'
        compiler.write_bytes(b'not executable')
        cold = self.directory / 'absent-cold.json'
        output = self.directory / 'output'
        result = self.invoke('--compiler', compiler, '--cold-report', cold,
                             '--output', output,
                             script=ROOT / 'tools/build_hia_agent_identity.py')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FileNotFoundError', result.stderr)
        self.assertIn(str(cold), result.stderr)
        self.assertNotIn('ModuleNotFoundError', result.stderr)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
