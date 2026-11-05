"""Explicit Linux-only controlled-I/O tests; no tunnel or artifact execution."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
DISPATCH = HERE.parent / 'udp64_dispatch'


class ReadinessTests(unittest.TestCase):
    observations = []

    @classmethod
    def setUpClass(cls):
        if not sys.platform.startswith('linux'):
            raise RuntimeError('actual Linux poll readiness is required; no skipped pass')
        cc = shutil.which('gcc')
        if not cc:
            raise RuntimeError('GCC is required; no skipped pass')
        cls.compiler = subprocess.run([cc, '--version'], check=True, capture_output=True,
                                      text=True, timeout=5).stdout.splitlines()[0]
        cls.tmp = tempfile.TemporaryDirectory(prefix='hepta-readiness-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binaries = {}
        candidate = (DISPATCH / 'candidate_process_io.c').read_text()
        needle = '&& c->c2.prefer_tun_read'
        if candidate.count(needle) != 1:
            raise RuntimeError('candidate tie predicate changed')
        mutation = Path(cls.tmp.name) / 'disabled_tie.c'
        mutation.write_text(candidate.replace(needle, '&& false /* controlled negative mutation */'))
        for opt in ('-O0', '-O3'):
            for variant, source in [('original', DISPATCH / 'upstream_process_io.c'),
                                    ('candidate', DISPATCH / 'candidate_process_io.c'),
                                    ('disabled_tie', mutation)]:
                binary = Path(cls.tmp.name) / (opt[1:] + '-' + variant)
                command = [cc, '-std=c11', opt, '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                           '-fsanitize=undefined', '-fno-sanitize-recover=all',
                           '-I' + str(HERE / 'shim'), '-I' + str(HERE / 'upstream'),
                           '-DDISPATCH_SOURCE="' + str(source) + '"',
                           str(HERE / 'readiness_harness.c'), '-o', str(binary)]
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)
                cls.binaries[opt, variant] = binary

    def run_case(self, opt, variant, scenario, require_fair=False):
        command = [str(self.binaries[opt, variant]), scenario]
        if require_fair:
            command.append('--require-fair')
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.stderr, '')
        document = json.loads(result.stdout)
        self.observations.append({'optimization': opt, 'variant': variant, 'scenario': scenario,
                                  'require_fair': require_fair, 'exit_code': result.returncode,
                                  'observation': document})
        return result.returncode, document

    def test_source_inputs(self):
        metadata = json.loads((HERE / 'source.json').read_text())
        for entry in metadata['inputs']:
            data = (HERE / entry['file']).read_bytes()
            self.assertEqual(len(data), entry['excerpt_bytes'])
            self.assertEqual(hashlib.sha256(data).hexdigest(), entry['excerpt_sha256'])
            if entry['file'] in ('upstream/event.c', 'upstream/event.h'):
                self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                                 entry['git_blob_sha1'])
        for name, expected in metadata['inherited_dispatch_inputs'].items():
            self.assertEqual(hashlib.sha256((DISPATCH / name).read_bytes()).hexdigest(), expected)

    def check_dual(self, result, fair):
        self.assertEqual(result['backend'], 'poll-fast')
        self.assertEqual(result['prefill_each'], 64)
        self.assertEqual(result['prefix_dispatches'], 96)
        self.assertEqual(result['dual_readiness_turns'], 48)
        self.assertEqual(result['final_link_deliveries'], 64)
        self.assertEqual(result['final_tun_deliveries'], 64)
        self.assertEqual(result['fair_prefix'], fair)
        self.assertEqual(result['prefix_link_reads'], 24 if fair else 48)
        self.assertEqual(result['prefix_tun_reads'], 24 if fair else 0)
        self.assertEqual(result['prefix_link_deliveries'], result['prefix_link_reads'])
        self.assertEqual(result['prefix_tun_deliveries'], result['prefix_tun_reads'])
        self.assertEqual(result['statuses'], [5, 12, 5, 3] * 24 if fair else [5, 12] * 48)
        self.assertEqual(result['actions'], [1, 2, 3, 4] * 24 if fair else [1, 2] * 48)

    def test_original_starves_tun_in_observed_dual_ready_prefix(self):
        for opt in ('-O0', '-O3'):
            with self.subTest(opt=opt):
                code, result = self.run_case(opt, 'original', 'dual', True)
                self.assertEqual(code, 23)
                self.check_dual(result, False)

    def test_candidate_services_both_actual_ready_queues(self):
        for opt in ('-O0', '-O3'):
            with self.subTest(opt=opt):
                code, result = self.run_case(opt, 'candidate', 'dual', True)
                self.assertEqual(code, 0)
                self.check_dual(result, True)

    def test_disabled_tie_restores_original_failure(self):
        for opt in ('-O0', '-O3'):
            with self.subTest(opt=opt):
                code, result = self.run_case(opt, 'disabled_tie', 'dual', True)
                self.assertEqual(code, 23)
                self.check_dual(result, False)

    def test_empty_and_single_direction(self):
        for opt in ('-O0', '-O3'):
            for variant in ('original', 'candidate'):
                for scenario in ('empty', 'link', 'tun'):
                    with self.subTest(opt=opt, variant=variant, scenario=scenario):
                        code, result = self.run_case(opt, variant, scenario)
                        self.assertEqual(code, 0)
                        if scenario == 'empty':
                            self.assertTrue(result['timeout'])
                        else:
                            self.assertEqual(result['delivered'], 64)
                            self.assertEqual(result['direction'], 0 if scenario == 'link' else 1)

    def test_pending_writes_and_real_socket_backpressure(self):
        for opt in ('-O0', '-O3'):
            for variant in ('original', 'candidate'):
                for scenario in ('pending', 'backpressure'):
                    with self.subTest(opt=opt, variant=variant, scenario=scenario):
                        code, result = self.run_case(opt, variant, scenario)
                        self.assertEqual(code, 0)
                        if scenario == 'pending':
                            self.assertTrue(result['socket_write_first'])
                        else:
                            self.assertTrue(0 < result['blocked_datagrams'] < 4096)
                            self.assertEqual(result['delivered'], 2)

    def test_independent_contexts_and_fresh_context(self):
        for opt in ('-O0', '-O3'):
            for variant in ('original', 'candidate'):
                with self.subTest(opt=opt, variant=variant):
                    code, result = self.run_case(opt, variant, 'isolation')
                    self.assertEqual(code, 0)
                    self.assertEqual(result['second_read'], 3 if variant == 'candidate' else 1)
                    self.assertEqual(result['reset_first_read'], 1)


if __name__ == '__main__':
    unittest.main()
