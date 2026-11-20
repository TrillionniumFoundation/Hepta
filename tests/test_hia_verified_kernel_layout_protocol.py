"""Complete layout inventory and driver checks without timing any kernel.

All 138 mode/length/layout combinations use --validate-only. These tests
exercise C references and malicious reference fixtures, not HIA performance.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


runner = module('benchmark_hia_verified_kernels_layout.py', 'layout_driver_runner_tests')
reader = module('read_hia_verified_kernel_layout_campaign_v7.py', 'layout_independent_reader_tests')
v6 = module('read_hia_verified_kernel_campaign_v6.py', 'layout_v6_inventory_tests')


class LayoutProtocolInventoryTests(unittest.TestCase):
    def test_complete_two_phase_inventory_and_original_controls_are_fixed(self):
        protocol = runner.read_protocol(ROOT)
        original = json.loads((ROOT / 'benchmarks/hia_verified_kernels/PROTOCOL.json').read_text())
        self.assertEqual(runner.original_inventory(), v6.expected_cases(original))
        self.assertEqual(runner.controlled_inventory(), reader.independent_layout_inventory(v6, original))
        self.assertEqual(reader.audit_protocol(ROOT, original), protocol)
        cases = runner.controlled_inventory()
        self.assertEqual(len(cases), 1518)
        self.assertEqual(sum(c['mode'] == 'copy' for c in cases), 1012)
        self.assertEqual(sum(c['mode'] != 'copy' for c in cases), 506)
        self.assertEqual((protocol['cases'], protocol['samples']), (2281, 47901))
        for mode, arm, length in runner.original_inventory():
            copies = [c for c in cases if (c['mode'], c['arm'], c['length']) == (mode, arm, length)]
            self.assertEqual(len(copies), 0 if mode == 'scalar' else 4 if mode == 'copy' else 1)
            if mode == 'copy':
                self.assertEqual({(c['gap'], c['address_order']) for c in copies},
                                 {(g, o) for g in (131072, 131136) for o in ('src-low', 'src-high')})

    def test_independent_prefix_checksum_matches_driver_sum_formula(self):
        protocol = {'lengths': runner.LENGTHS, 'span_iterations': {str(n): 17 for n in runner.LENGTHS}}
        expected = reader.independent_checksums(protocol)
        for mode in ('sum', 'zero', 'copy'):
            for length in runner.LENGTHS:
                self.assertEqual(runner.checksum(mode, length, 17), expected[mode, length])


class LayoutDriverFunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(os, 'sched_getaffinity') or not shutil.which('gcc'):
            raise RuntimeError('layout functional qualification requires Linux affinity and GCC; skips are not qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-layout-functional-')
        cls.directory = Path(cls.temporary.name)
        cls.driver = cls.directory / 'driver-layout'
        cls.reference = cls.directory / 'reference.so'
        cls.cpu = min(os.sched_getaffinity(0))
        subprocess.run(['gcc', '-O3', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        str(ROOT / 'benchmarks/hia_verified_kernels/driver_layout.c'), '-ldl', '-o', str(cls.driver)],
                       check=True, capture_output=True)
        subprocess.run(['gcc', '-O3', '-fPIC', '-shared', str(ROOT / 'benchmarks/hia_verified_kernels/reference.c'),
                        '-o', str(cls.reference)], check=True, capture_output=True)
        bad = cls.directory / 'bad.c'
        bad.write_text('''#include <stdint.h>
#include <string.h>
uint64_t bad_length(uint8_t*d,uint64_t de,const uint8_t*s,uint64_t se,uint64_t n){
  (void)de;(void)se;memcpy(d,s,n);return n+1;
}
uint64_t bad_byte(uint8_t*d,uint64_t de,const uint8_t*s,uint64_t se,uint64_t n){
  (void)de;(void)se;memcpy(d,s,n);if(n)d[0]^=1;return n;
}
uint64_t bad_outside(uint8_t*d,uint64_t de,const uint8_t*s,uint64_t se,uint64_t n){
  (void)de;(void)se;memcpy(d,s,n);d[n]=0;return n;
}
''')
        cls.bad = cls.directory / 'bad.so'
        subprocess.run(['gcc', '-O3', '-fPIC', '-shared', str(bad), '-o', str(cls.bad)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def execute(self, mode, length, gap=131072, order='src-low', *, library=None, symbol=None, batches='21', calls='17'):
        return subprocess.run([str(self.driver), mode, str(library or self.reference), symbol or 'reference_' + mode,
                               batches, calls, str(length), str(gap), order, '--validate-only'],
                              preexec_fn=lambda: os.sched_setaffinity(0, {self.cpu}),
                              capture_output=True, text=True, timeout=10)

    def test_all_138_length_and_layout_combinations_have_no_timed_samples(self):
        expected = reader.independent_checksums({'lengths': runner.LENGTHS,
                                                 'span_iterations': {str(n): 17 for n in runner.LENGTHS}})
        count = 0
        for mode in ('sum', 'zero', 'copy'):
            variants = [(g, o) for g in (131072, 131136) for o in ('src-low', 'src-high')] if mode == 'copy' else [(131072, 'src-low')]
            for length in runner.LENGTHS:
                for gap, order in variants:
                    with self.subTest(mode=mode, length=length, gap=gap, order=order):
                        process = self.execute(mode, length, gap, order)
                        self.assertEqual(process.returncode, 0, process.stderr)
                        records = [json.loads(line) for line in process.stdout.splitlines()]
                        self.assertEqual(len(records), 2)
                        observed, check = records
                        self.assertTrue(observed['validation_only'])
                        self.assertTrue(observed['arena_allocated_before_dlopen'])
                        self.assertEqual(observed['cpu'], self.cpu)
                        self.assertEqual(observed['arena_base'] % 4096, 0)
                        self.assertEqual(observed['lower_base'], observed['arena_base'] + 4096)
                        self.assertEqual(observed['upper_base'], observed['lower_base'] + gap)
                        source, destination = ((observed['upper_base'], observed['lower_base']) if order == 'src-high'
                                               else (observed['lower_base'], observed['upper_base']))
                        self.assertEqual((observed['source_base'], observed['destination_base']), (source, destination))
                        self.assertEqual(observed['destination_minus_source'], destination - source)
                        for prefix, address in (('source', source), ('destination', destination)):
                            self.assertEqual(observed[prefix + '_mod64'], address % 64)
                            self.assertEqual(observed[prefix + '_mod4096'], address % 4096)
                        self.assertEqual(check, {'record': 'validation', 'ok': True, 'timed_samples': 0,
                                                 'length': length, 'offsets_checked': 16, 'checksum': expected[mode, length]})
                        self.assertNotIn('elapsed_ns', process.stdout)
                        count += 1
        self.assertEqual(count, 138)

    def test_invalid_workload_extent_gap_order_and_counts_reject_before_loading(self):
        controls = [dict(mode='scalar', length=1), dict(mode='copy', length=65537),
                    dict(mode='copy', length=-1), dict(mode='copy', length=1, gap=131073),
                    dict(mode='copy', length=1, order='unordered'), dict(mode='sum', length=1, order='src-high'),
                    dict(mode='zero', length=1, gap=131136), dict(mode='copy', length=1, batches='20'),
                    dict(mode='copy', length=1, calls='0')]
        for control in controls:
            with self.subTest(control=control):
                process = self.execute(**control, library=self.directory / 'missing.so')
                self.assertEqual(process.returncode, 3)
                self.assertEqual(process.stdout, '')

    def test_actual_allocation_receipt_precedes_a_failed_library_load(self):
        process = self.execute('copy', 65536, 131136, 'src-high', library=self.directory / 'missing.so')
        self.assertEqual(process.returncode, 5)
        records = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]['arena_allocated_before_dlopen'])
        self.assertEqual(records[0]['destination_minus_source'], -131136)

    def test_wrong_copy_return_bytes_and_outside_effects_are_rejected_untimed(self):
        for symbol, status in (('bad_length', 9), ('bad_byte', 10), ('bad_outside', 14)):
            with self.subTest(symbol=symbol):
                process = self.execute('copy', 17, 131136, 'src-high', library=self.bad, symbol=symbol)
                self.assertEqual(process.returncode, status)
                self.assertNotIn('elapsed_ns', process.stdout)
                self.assertEqual(len(process.stdout.splitlines()), 1)


if __name__ == '__main__':
    unittest.main()
