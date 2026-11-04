"""Executable current-behavior counterexamples, not an enabled CLI adapter.

Scoped test injections expose where naive owner substitution loses authority.
No production function, command default, or native publication is modified.
"""
from contextlib import redirect_stdout
from dataclasses import asdict
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import cli, modules, packages, pipeline
from hepta.ast import HeptaError
from experiments.package_copy.owner import Owner, Limits
from experiments.request_load.context import Rejected

TEXT = 'fn main()->Unit effects {} {}'


class CLIClosureAudit(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text(TEXT)

    def package(self):
        (self.root / 'hepta.toml').write_text(
            '[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def test_naive_pipeline_load_substitution_leaves_final_reads_unowned(self):
        owner = Owner(); after_load = []
        def substitute(entry, **options):
            handle = owner.load(entry, **options)
            after_load.append((owner.context.reader.reads, owner.context.reader.bytes_read))
            return handle.project
        with patch.object(modules, 'load_project', substitute):
            result = pipeline.analyze_project(self.entry, native=False)
        self.assertTrue(result.report['ok'])
        self.assertEqual(after_load[-1], (owner.context.reader.reads, owner.context.reader.bytes_read))
        handle = owner._handles[0][0]
        self.assertTrue(handle.unchanged())
        self.assertGreater(owner.context.reader.reads, after_load[-1][0])
        self.assertGreater(owner.context.reader.bytes_read, after_load[-1][1])

    def test_cli_does_not_translate_current_admission_exception(self):
        output = io.StringIO()
        with patch.object(cli, 'analyze_project', side_effect=Rejected('source quota exceeded')):
            with redirect_stdout(output), self.assertRaises(Rejected):
                cli.main(['check', str(self.entry), '--frontend-only'])
        self.assertEqual(output.getvalue(), '')

    def test_cli_resolves_original_entry_alias_before_pipeline(self):
        alias = self.root / 'alias.hepta'; alias.symlink_to(self.entry)
        seen = []
        original = pipeline.analyze_project
        def observe(entry, **options):
            seen.append(entry)
            return original(entry, **options)
        output = io.StringIO()
        with patch.object(cli, 'analyze_project', observe), redirect_stdout(output):
            code = cli.main(['check', str(alias), '--frontend-only'])
        self.assertEqual(code, 0)
        self.assertEqual(seen, [self.entry.resolve()])
        handle = Owner().load(alias)
        self.assertEqual(handle.project.bindings[str(alias.absolute())], str(self.entry.resolve()))

    def test_raw_entry_handle_detects_late_alias_retarget(self):
        alias = self.root / 'alias.hepta'; alias.symlink_to(self.entry)
        other = self.root / 'other.hepta'; other.write_text(TEXT)
        handle = Owner().load(alias)
        alias.unlink(); alias.symlink_to(other)
        self.assertFalse(handle.unchanged())

    def test_cli_second_build_has_no_final_source_revalidation(self):
        analysis = pipeline.analyze_project(self.entry, native=False)
        seen = []; output = io.StringIO(); destination = self.root / 'out'
        def fake_compile(source, **options):
            self.entry.write_text(TEXT + '\n// changed during second compilation\n')
            seen.append(options['output'])
            return {'ok': True, 'artifact': str(options['output'])}
        with patch.object(cli, 'analyze_project', return_value=analysis), \
             patch.object(cli, 'compile_rust', fake_compile), redirect_stdout(output):
            code = cli.main(['build', str(self.entry), '--output', str(destination)])
        self.assertEqual(code, 0)
        self.assertEqual(seen, [destination.resolve()])
        self.assertTrue(json.loads(output.getvalue())['ok'])
        self.assertFalse(analysis.project.unchanged())
        self.assertFalse(destination.exists())  # Fake compiler never publishes.

    def test_owned_final_revalidation_detects_analysis_time_source_change(self):
        owner = Owner(); handle = owner.load(self.entry)
        result = pipeline.analyze(TEXT, str(handle.project.entry), native=False, loaded_project=handle.project)
        self.assertTrue(result.report['ok'])
        self.entry.write_text(TEXT + '\n// changed\n')
        self.assertFalse(handle.unchanged())

    def test_final_revalidation_uses_remaining_read_allowance(self):
        probe = Owner(); probe.load(self.entry); initial_reads = probe.context.reader.reads
        owner = Owner(Limits(reads=initial_reads)); handle = owner.load(self.entry)
        with self.assertRaises(Rejected):handle.unchanged()
        self.assertTrue(owner.context.closed)
        with self.assertRaisesRegex(Rejected, 'terminal'):handle.unchanged()

    def test_late_lock_only_mutation_is_not_fresh_lock_verification(self):
        self.package(); packages.write_lock(self.root)
        handle = Owner().load(self.entry, locked=True)
        (self.root / 'Hepta.lock').write_text('{}')
        self.assertTrue(handle.unchanged())
        with self.assertRaises(HeptaError):packages.verify_lock(packages.load_package(self.root))

    def test_public_source_authority_mutation_does_not_hide_disk_change(self):
        handle = Owner().load(self.entry)
        handle.project.source_bytes.clear(); handle.project.bindings.clear()
        self.entry.write_text(TEXT + '\n// changed\n')
        self.assertFalse(handle.unchanged())

    def test_unchanged_is_not_mutable_ast_authentication(self):
        handle = Owner().load(self.entry)
        handle.project.program.functions.clear()
        self.assertTrue(handle.unchanged())

    def test_overrides_refused_before_reader_use(self):
        for overrides in ({}, {str(self.entry): TEXT}):
            owner = Owner()
            with self.assertRaises(Rejected):owner.load(self.entry, source_overrides=overrides)
            self.assertEqual(owner.context.reader.reads, 0)
            self.assertEqual(owner._handles, [])

    def test_cross_thread_owner_use_is_terminal(self):
        owner = Owner(); errors = []
        def worker():
            try:owner.load(self.entry)
            except BaseException as error:errors.append(error)
        thread = threading.Thread(target=worker); thread.start(); thread.join(timeout=5)
        self.assertFalse(thread.is_alive()); self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Rejected)
        self.assertTrue(owner.context.closed); self.assertEqual(owner.context.reader.reads, 0)
        with self.assertRaisesRegex(Rejected, 'terminal'):owner.load(self.entry)

    def test_current_terminal_error_does_not_preserve_first_reason(self):
        owner = Owner(Limits(source=1))
        with self.assertRaises(Rejected) as first:owner.load(self.entry)
        with self.assertRaises(Rejected) as later:owner.load(self.entry)
        self.assertNotEqual(str(first.exception), str(later.exception))
        self.assertEqual(str(later.exception), 'request context is terminal')
        self.assertFalse(hasattr(first.exception, 'diagnostic'))

    def test_path_pins_assume_trusted_import_bootstrap(self):
        # Deliberately corrupt before profile bootstrap in an isolated process.
        # This is a documented trust-boundary counterexample, not a desired
        # supported mutation or a claim of arbitrary-runtime protection.
        script = '''
import pathlib
pathlib.PurePath.__reduce__ = lambda self: (str, ('bootstrap replacement',))
from experiments.package_copy.owner import Owner, _COPY
from hepta.packages import Package
p = pathlib.Path('/a'); p.parts
root = Package(p, 'x', '1.0.0', p, 'lib', p)
result = Owner()._authority_copy(_COPY, root, 'package')
assert result.root == 'bootstrap replacement'
'''
        result = subprocess.run([sys.executable, '-B', '-c', script], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_c_header_parser_entry_has_separate_direct_reader(self):
        from hepta import c_import
        header = self.root / 'sample.h'; header.write_text('int sample(int value);\n')
        owner = Owner(); seen = []
        def stop_after_materialization(text):
            seen.append(text)
            raise RuntimeError('stop before native compiler')
        with patch.object(c_import, 'HeaderParser', stop_after_materialization), \
             patch.object(c_import, '_native_process', side_effect=AssertionError('native invoked')):
            with self.assertRaisesRegex(RuntimeError, 'stop before native compiler'):
                c_import.import_header(header)
        self.assertEqual(seen, ['int sample(int value);\n'])
        self.assertEqual(owner.context.reader.reads, 0)
        self.assertEqual(owner.context.counts['parses'], 0)

    def test_current_runtime_guard_is_late_not_pre_io(self):
        from experiments.package_copy import owner as profile
        owner = Owner()
        with patch.object(profile, '_SUPPORTED', False), self.assertRaisesRegex(Rejected, 'unsupported Package copy runtime'):
            owner.load(self.entry)
        self.assertGreater(owner.context.reader.reads, 0)
        self.assertEqual(owner._handles, [])

    def test_named_policy_units_are_all_positive_but_not_one_memory_limit(self):
        values = asdict(Limits())
        self.assertGreater(len(values), 30)
        self.assertTrue(all(type(value) is int and value > 0 for value in values.values()))
        for dimension in ('total_bytes', 'reads', 'module_edges', 'total_tokens', 'ast_nodes',
                          'parser_appends', 'copy_visits', 'transform_visits', 'authority_visits',
                          'shallow_fields', 'package_copy_calls'):
            self.assertIn(dimension, values)
        self.assertNotIn('heap_bytes', values); self.assertNotIn('deadline_seconds', values)


if __name__ == '__main__':unittest.main()
