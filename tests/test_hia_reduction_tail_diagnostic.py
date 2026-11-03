"""Paired clocks are diagnostic evidence, never a substitute release gate."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools import diagnose_hia_reduction_tails as diagnostic


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.request = dict(workload='linear', n=0, seed=7, calls=1, samples=2, warmup=3)
        self.row = {k: self.request[k] for k in ('n', 'seed', 'calls', 'samples', 'warmup')}
        self.row.update(wall_resolution_ns=1, cpu_resolution_ns=1,
                        observations=[dict(wall_ns=10, cpu_envelope_ns=100, checksum=0) for _ in range(2)])

    def test_cpu_envelope_can_exceed_wall_for_short_work(self):
        self.assertIs(diagnostic.inspect_response(self.row, self.request), self.row)

    def test_rejects_changed_identity_including_bool(self):
        for key in ('n', 'seed', 'calls', 'samples', 'warmup'):
            for value in (True, 0.0, self.request[key] + 1):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    row = deepcopy(self.row); row[key] = value
                    diagnostic.inspect_response(row, self.request)

    def test_rejects_incomplete_samples_and_invalid_values(self):
        mutations = [lambda r: r['observations'].pop(),
                     lambda r: r['observations'][0].update(checksum=1),
                     lambda r: r['observations'][0].update(wall_ns=-1),
                     lambda r: r['observations'][0].update(cpu_envelope_ns=True),
                     lambda r: r['observations'][0].update(extra=0),
                     lambda r: r.update(cpu_resolution_ns=0)]
        for mutation in mutations:
            row = deepcopy(self.row); mutation(row)
            with self.assertRaises(ValueError): diagnostic.inspect_response(row, self.request)


@unittest.skipUnless(shutil.which('gcc'), 'native diagnostic control needs existing GCC')
class NativeClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(); cls.root = Path(cls.temp.name)
        cls.driver = cls.root / 'driver'; cls.library = cls.root / 'control.so'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(diagnostic.DRIVER), '-ldl', '-o', str(cls.driver)], check=True)
        source = cls.root / 'control.c'
        source.write_text('''#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <time.h>
static uint64_t cpu(void) {struct timespec t; clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
uint64_t calculate(size_t n, uint32_t seed) {
 (void)seed;
 if(n==0) {struct timespec delay={0,5000000}; nanosleep(&delay,0);}
 else {uint64_t start=cpu(); while(cpu()-start<5000000) {}}
 return 0;
}
''')
        subprocess.run(['gcc', '-std=c11', '-O2', '-shared', '-fPIC', str(source),
                        '-o', str(cls.library)], check=True)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def observe(self, n):
        return json.loads(subprocess.check_output([str(self.driver), str(self.library), str(n), '7', '1', '3', '0'], text=True))

    def test_sleep_control_has_positive_wall_minus_cpu_gap(self):
        row = self.observe(0)
        request = dict(workload='linear', n=0, seed=7, calls=1, samples=3, warmup=0)
        diagnostic.inspect_response(row, request)
        for sample in row['observations']:
            self.assertGreater(sample['wall_ns'] - sample['cpu_envelope_ns'], 1000000)

    def test_busy_control_records_cpu_work_without_assuming_exclusive_host(self):
        for sample in self.observe(1)['observations']:
            self.assertGreaterEqual(sample['cpu_envelope_ns'], 5000000)
            self.assertGreater(sample['wall_ns'], 0)

    def test_rejects_invalid_request_before_loading(self):
        for args in [('0','7','0','3','0'), ('0','7','1','65','0'), ('-1','7','1','3','0'), ('0','4294967296','1','3','0')]:
            result = subprocess.run([str(self.driver), '/nonexistent', *args], capture_output=True)
            self.assertEqual(result.returncode, 64)

if __name__ == '__main__': unittest.main()
