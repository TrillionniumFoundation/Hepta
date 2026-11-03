"""Native-host identity and finite upstream observation refusal contracts."""
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected
from hepta.cpp_host_toolchain import parse_probe
from tools.qualify_cpp_upstream_host import (casefold_path_collisions, check_observation,
    inspect_executable, qualify, require_clean_checkout, require_same_clean_checkout,
    source_checkout_identity, validate_report)
from tools.qualify_cpp_upgrade import FIXTURES, expected_rows, locked_libraries


class CppUpstreamHostTests(unittest.TestCase):
    @contextmanager
    def checkout(self):
        with tempfile.TemporaryDirectory(prefix='hepta-clean-source-') as td:
            root = Path(td)
            def git(*arguments):
                return subprocess.check_output(['git', '-C', str(root), *arguments], stderr=subprocess.STDOUT)
            git('init', '--quiet')
            git('config', 'core.autocrlf', 'false')
            (root / 'input.hepta').write_bytes(b'original input\n')
            git('add', 'input.hepta')
            git('-c', 'user.name=Checkout fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '--quiet', '-m', 'clean initial source')
            yield root, git

    def probe(self, family='gcc', system='Linux', machine='x86_64'):
        return (f'HEPTA_CXX_FAMILY {family}\nHEPTA_CXX_VERSION '
                + ('194133823 0' if family == 'msvc' else '18 1 8')
                + f'\nHEPTA_CXX_SYSTEM {system}\nHEPTA_CXX_MACHINE {machine}\nHEPTA_CXX_STANDARD 202002L\n')

    def observed(self):
        return {'version': '3.12.0', 'cases': expected_rows(), 'lifecycle_cases': 32,
                'borrowed_input_overwritten': 32, 'stale_reads': 32, 'duplicate_destroys': 32,
                'refused_mutations': 64, 'pointer_guards': 4, 'malformed_constructor': 1,
                'cancellation': {'requested': 7, 'committed': 3, 'value': 107, 'replayed': 0},
                'concurrent_calls': 1024, 'ordinary_live_delta': 0,
                'registry_ordinary_allocations_retained': 2}

    def test_distinguishes_actual_clang_from_microsoft_driver(self):
        self.assertEqual(parse_probe(self.probe('clang', 'Windows'))['family'], 'clang')
        self.assertEqual(parse_probe(self.probe('msvc', 'Windows'))['family'], 'msvc')

    def test_rejects_duplicate_missing_or_unsupported_compiler_markers(self):
        for text in [self.probe() + 'HEPTA_CXX_FAMILY gcc\n',
                     self.probe().replace('HEPTA_CXX_MACHINE x86_64\n', ''),
                     self.probe(machine='riscv64'), self.probe(family='unknown'),
                     self.probe('msvc', 'Linux'), self.probe().replace('202002L', '201703L')]:
            with self.subTest(text=text), self.assertRaises(MigrationRejected):
                parse_probe(text)

    def test_complete_upstream_original_bytes_and_licenses_are_pinned(self):
        self.assertEqual([r['version'] for r in locked_libraries()], ['3.11.3', '3.12.0'])

    def test_windows_autocrlf_checkout_preserves_locked_upstream_bytes(self):
        # Exercise actual Git checkout conversion on every host. This is an
        # input-identity test; it does not simulate Windows C++ execution.
        attributes = (Path(__file__).resolve().parents[1] / '.gitattributes').read_bytes()
        original = {p.relative_to(FIXTURES): p.read_bytes()
                    for p in FIXTURES.rglob('*') if p.is_file()}
        for protected, selected in [(False, b''), (True, attributes)]:
            with self.subTest(protected=protected), tempfile.TemporaryDirectory(prefix='hepta-cpp-checkout-') as td:
                base = Path(td)
                seed, checkout = base / 'seed', base / 'checkout'
                seed.mkdir()
                shutil.copytree(FIXTURES, seed / 'tests/fixtures/cpp_upgrade')
                (seed / '.gitattributes').write_bytes(selected)
                empty_config = base / 'empty-git-config'
                empty_config.write_bytes(b'')
                env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1',
                           GIT_CONFIG_GLOBAL=str(empty_config), GIT_ATTR_NOSYSTEM='1')
                def git(cwd, *arguments):
                    process = subprocess.run(['git', '-C', str(cwd), *arguments],
                                             env=env, capture_output=True, timeout=30)
                    self.assertEqual(process.returncode, 0,
                                     (process.stdout + process.stderr).decode(errors='replace'))
                    return process.stdout
                git(seed, 'init', '--quiet')
                git(seed, 'config', 'user.name', 'Upstream checkout fixture')
                git(seed, 'config', 'user.email', 'fixture@example.invalid')
                git(seed, '-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', 'add', '.')
                git(seed, 'commit', '--quiet', '-m', 'original upstream bytes')
                git(base, 'clone', '--quiet', '--no-hardlinks', '--config', 'core.autocrlf=true',
                    str(seed), str(checkout))
                self.assertEqual(git(checkout, 'config', '--get', 'core.autocrlf').strip(), b'true')
                directory = checkout / 'tests/fixtures/cpp_upgrade'
                if not protected:
                    # Reproduce the old Windows preflight failure. Do not
                    # normalize changed bytes or relax the pinned SHA values.
                    self.assertNotEqual((directory / '3.11.3/json.hpp').read_bytes(),
                                        original[Path('3.11.3/json.hpp')])
                    with self.assertRaisesRegex(ValueError, 'upstream header content differs'):
                        locked_libraries(directory)
                    continue
                self.assertEqual([row['version'] for row in locked_libraries(directory)],
                                 ['3.11.3', '3.12.0'])
                for relative, raw in original.items():
                    self.assertEqual((directory / relative).read_bytes(), raw, str(relative))
                for name, error in [('3.11.3/json.hpp', 'upstream header content differs'),
                                    ('3.11.3/LICENSE.MIT', 'license identity differs')]:
                    path = directory / name
                    path.write_bytes(original[Path(name)] + b'changed')
                    with self.assertRaisesRegex(ValueError, error):
                        locked_libraries(directory)
                    path.write_bytes(original[Path(name)])

    def test_observation_keeps_registry_retention_separate_from_completed_owners(self):
        check_observation(self.observed(), '3.12.0')
        for key, wrong in [('registry_ordinary_allocations_retained', 0), ('ordinary_live_delta', 1),
                           ('ordinary_live_delta', False), ('concurrent_calls', 0),
                           ('borrowed_input_overwritten', 31), ('lifecycle_cases', 31)]:
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError):
                changed = self.observed()
                changed[key] = wrong
                check_observation(changed, '3.12.0')

    def test_cancellation_does_not_accept_replay_or_uncommitted_state(self):
        for key, wrong in [('committed', 7), ('replayed', 1), ('value', 108)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                changed = self.observed()
                changed['cancellation'][key] = wrong
                check_observation(changed, '3.12.0')

    def test_wrong_native_value_and_deleted_inputs_are_refused(self):
        for mutate in [lambda r: r['cases'].pop(),
                       lambda r: r['cases'][0].update(hepta_value=0),
                       lambda r: r.update(version='3.11.3'),
                       lambda r: r.update(foreign_memory_safety_proved=True)]:
            changed = copy.deepcopy(self.observed())
            mutate(changed)
            with self.assertRaises(ValueError):
                check_observation(changed, '3.12.0')

    def test_actual_executable_header_must_match_the_reported_host(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'artifact'
            data = bytearray(64)
            data[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<HH', data, 16, 3, 62)
            p.write_bytes(data)
            self.assertEqual(inspect_executable(p, 'Linux', 'x86_64')['format'], 'ELF64')
            for system, machine in [('Linux', 'aarch64'), ('Windows', 'x86_64'), ('Darwin', 'x86_64')]:
                with self.subTest(system=system), self.assertRaises(ValueError):
                    inspect_executable(p, system, machine)
            p.write_bytes(data[:20])
            with self.assertRaises(ValueError):
                inspect_executable(p, 'Linux', 'x86_64')

    def test_wrong_expected_host_stops_before_any_tool_runs(self):
        with tempfile.TemporaryDirectory() as td, patch('tools.qualify_cpp_upstream_host.platform.system', return_value='Linux'), \
                patch('tools.qualify_cpp_upstream_host._run') as run:
            report = qualify(Path(td) / 'rejected', expected_system='Windows')
            self.assertFalse(report['ok'])
            self.assertFalse(report['claims']['actual_reported_host_executed'])
            self.assertEqual(report['versions'], [])
            run.assert_not_called()

    def test_all_tracked_paths_and_directory_prefixes_are_casefold_unique(self):
        root = Path(__file__).resolve().parents[1]
        raw = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root)
        self.assertEqual(casefold_path_collisions(raw.decode().rstrip('\0').split('\0')), [])
        for paths in [('archive/BASE.json', 'archive/base.json'),
                      ('Archive/one.json', 'archive/two.json'),
                      ('Output', 'output/child.json')]:
            with self.subTest(paths=paths):
                self.assertTrue(casefold_path_collisions(paths))
        self.assertEqual(casefold_path_collisions(('archive/BASE_PROGRAM.json', 'archive/base.json')), [])

    def test_dirty_checkout_stops_before_any_compiler_or_input_capture(self):
        with self.checkout() as (root, git):
            require_clean_checkout(source_checkout_identity(root))
            (root / 'input.hepta').write_bytes(b'changed tracked input\n')
            with patch('tools.qualify_cpp_upstream_host.ROOT', root), \
                    patch('tools.qualify_cpp_upstream_host._run') as run, \
                    patch('tools.qualify_cpp_upstream_host.compiler_identity') as compiler, \
                    patch('tools.qualify_cpp_upstream_host.source_inputs') as inputs:
                report = qualify(root / 'untracked-evidence')
            self.assertFalse(report['ok'])
            self.assertFalse(report['claims']['actual_reported_host_executed'])
            self.assertEqual(report['versions'], [])
            self.assertIn('not clean', report['error'])
            self.assertTrue(report['source_checkout_before']['tracked_status'])
            run.assert_not_called()
            compiler.assert_not_called()
            inputs.assert_not_called()

    def test_checkout_pair_refuses_end_drift_same_dirty_state_and_missing_evidence(self):
        with self.checkout() as (root, git):
            before = source_checkout_identity(root)
            require_same_clean_checkout(before, source_checkout_identity(root))
            (root / 'untracked-evidence.json').write_bytes(b'generated output\n')
            require_same_clean_checkout(before, source_checkout_identity(root))
            (root / 'input.hepta').write_bytes(b'changed tracked input\n')
            dirty = source_checkout_identity(root)
            for first, last in [(before, dirty), (dirty, dirty), (None, before), (before, None)]:
                with self.subTest(first=first, last=last), self.assertRaises(ValueError):
                    require_same_clean_checkout(first, last)
            git('add', 'input.hepta')
            git('-c', 'user.name=Checkout fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '--quiet', '-m', 'different clean source')
            after = source_checkout_identity(root)
            require_clean_checkout(after)
            with self.assertRaisesRegex(ValueError, 'changed during qualification'):
                require_same_clean_checkout(before, after)

    def test_report_validator_rejects_equal_dirty_and_current_drift_before_other_checks(self):
        with self.checkout() as (root, git):
            clean = source_checkout_identity(root)
            (root / 'input.hepta').write_bytes(b'changed tracked input\n')
            dirty = source_checkout_identity(root)
            for before, after, current in [(dirty, dirty, dirty), (clean, dirty, dirty),
                                            (clean, clean, dirty), (clean, None, clean)]:
                report = {'source_checkout_before': before, 'source_checkout_after': after}
                with self.subTest(before=before, after=after), \
                        patch('tools.qualify_cpp_upstream_host.source_checkout_identity', return_value=current), \
                        patch('tools.qualify_cpp_upstream_host.compiler_hash') as compiler, \
                        patch('tools.qualify_cpp_upstream_host.source_inputs') as inputs, \
                        self.assertRaises(ValueError):
                    validate_report(report)
                compiler.assert_not_called()
                inputs.assert_not_called()
            colliding = dict(clean, casefold_collisions=[['BASE.json', 'base.json']])
            with self.assertRaisesRegex(ValueError, 'collide under casefold'):
                require_same_clean_checkout(colliding, colliding)

    def test_archived_program_path_migrations_preserve_all_original_bytes(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'docs/HIA_ARCHIVE_PATH_MIGRATIONS.json').read_bytes())
        tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0'))
        self.assertEqual(len(manifest['migrations']), 2)
        for row in manifest['migrations']:
            with self.subTest(path=row['original_path']):
                self.assertNotIn(row['original_path'], tracked)
                self.assertIn(row['current_path'], tracked)
                for path, size, expected in [(row['current_path'], row['bytes'], row['sha256']),
                        (row['unchanged_receipt']['path'], row['unchanged_receipt']['bytes'], row['unchanged_receipt']['sha256'])]:
                    # The composition runner may use a sparse checkout. Its
                    # full tracked index still pins these historical bytes.
                    raw = subprocess.check_output(['git', 'show', ':' + path], cwd=root)
                    self.assertEqual(len(raw), size)
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
                    if (root / path).exists():
                        self.assertEqual((root / path).read_bytes(), raw)

    def test_generator_import_without_resource_and_measurement_refuses(self):
        import sys
        code = """
import sys
sys.modules['resource'] = None
from tools import qualify_hia_ndu_graph, qualify_hia_ndu_loop
ran = []
ledger = []
try:
    qualify_hia_ndu_loop.measured('fixture', ledger, lambda: ran.append(True))
except ModuleNotFoundError:
    pass
else:
    raise AssertionError('missing child accounting accepted')
assert ran == [] and ledger == []
"""
        subprocess.run([sys.executable, '-c', code], check=True,
                       cwd=Path(__file__).resolve().parents[1])

    def test_active_ndu_generators_publish_distinct_program_and_receipt_paths(self):
        from tools import qualify_hia_ndu_graph as graph, qualify_hia_ndu_loop as loop
        for module, target in [(loop, 'tools.qualify_hia_ndu_loop.NduBridge'),
                               (graph, 'tools.qualify_hia_ndu_graph.NduBridge.for_finite_profile')]:
            with self.subTest(generator=module.__name__), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                identity = root / 'identity.json'
                identity.write_text(json.dumps({'binary': 'must-not-execute'}))
                output = root / 'output'
                with patch(target, side_effect=RuntimeError('stop before native admission')) as native, \
                        self.assertRaisesRegex(RuntimeError, 'stop before native admission'):
                    module.qualify(output, identity=identity, clang='must-not-execute')
                native.assert_called_once()
                source = output / 'BASE_PROGRAM.json'
                original = source.read_bytes()
                self.assertIn('functions', json.loads(original))
                receipt = {'receipt': 'separate native observation fixture'}
                loop.save(output / 'base.json', receipt)
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(json.loads((output / 'base.json').read_bytes()), receipt)
                self.assertEqual(casefold_path_collisions(p.name for p in output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
