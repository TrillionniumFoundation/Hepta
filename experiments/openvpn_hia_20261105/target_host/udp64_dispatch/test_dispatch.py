"""Offline native dispatch controls. Never runs artifact files or real networking."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class DispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which('gcc')
        if cls.cc is None:
            raise RuntimeError('GCC is required; unavailable is not a skipped pass')
        cls.tmp = tempfile.TemporaryDirectory(prefix='hepta-dispatch-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binaries = {}
        for opt in ('-O0', '-O3'):
            for candidate in (False, True):
                binary = Path(cls.tmp.name) / (opt[1:] + ('-candidate' if candidate else '-original'))
                command = [cls.cc, '-std=c11', opt, '-Wall', '-Wextra', '-Werror',
                           '-fsanitize=undefined', '-fno-sanitize-recover=all']
                if candidate:
                    command.append('-DCANDIDATE=1')
                subprocess.run([*command, str(HERE / 'dispatch_harness.c'), '-o', str(binary)],
                               check=True, capture_output=True, text=True, timeout=20)
                cls.binaries[opt, candidate] = binary

    def run_model(self, opt, candidate, require_fair=False):
        result = subprocess.run([str(self.binaries[opt, candidate]), *(['--require-fair'] if require_fair else [])],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.stderr, '')
        return result.returncode, json.loads(result.stdout)

    def test_source_commitments(self):
        meta = json.loads((HERE / 'source.json').read_text())
        for name, key in [('upstream_process_io.c', 'upstream_excerpt_sha256'),
                          ('candidate_process_io.c', 'candidate_sha256')]:
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), meta[key])

    def test_original_keeps_finite_starvation_counterexample(self):
        for opt in ('-O0', '-O3'):
            with self.subTest(opt=opt):
                code, result = self.run_model(opt, False)
                self.assertEqual(code, 0)
                self.assertEqual(result, {'dispatch_controls': 512, 'iterations': 10000,
                                         'socket_reads': 5000, 'tun_reads': 0,
                                         'socket_writes': 0, 'tun_writes': 5000, 'fair_model': False})

    def test_fairness_requirement_is_red_on_original(self):
        for opt in ('-O0', '-O3'):
            with self.subTest(opt=opt):
                code, result = self.run_model(opt, False, require_fair=True)
                self.assertEqual(code, 23)
                self.assertFalse(result['fair_model'])

    def test_candidate_is_fair_only_in_dispatch_model(self):
        for opt in ('-O0', '-O3'):
            with self.subTest(opt=opt):
                code, result = self.run_model(opt, True, require_fair=True)
                self.assertEqual(code, 0)
                self.assertEqual(result, {'dispatch_controls': 512, 'iterations': 10000,
                                         'socket_reads': 2500, 'tun_reads': 2500,
                                         'socket_writes': 2500, 'tun_writes': 2500, 'fair_model': True})


if __name__ == '__main__':
    unittest.main()
