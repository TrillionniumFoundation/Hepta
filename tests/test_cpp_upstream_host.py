"""Native-host identity and finite upstream observation refusal contracts."""
import copy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected
from hepta.cpp_host_toolchain import parse_probe
from tools.qualify_cpp_upstream_host import check_observation, inspect_executable, qualify
from tools.qualify_cpp_upgrade import expected_rows, locked_libraries


class CppUpstreamHostTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
