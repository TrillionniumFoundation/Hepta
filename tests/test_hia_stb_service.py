"""Regression checks for the whole-module service contract and honest evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_stb_service as q


class StbServiceContractTests(unittest.TestCase):
    def test_disjoint_frozen_training_evaluation_and_explicit_error_domain(self):
        p = q.specification()
        c = q.corpora(p)
        self.assertEqual(len(c['training']), 129)
        self.assertEqual(len(c['evaluation']), 257)
        training = {(r['a'], r['b']) for r in c['training']}
        evaluation = {(r['a'], r['b']) for r in c['evaluation']}
        self.assertFalse(training & evaluation)
        self.assertIn((q.MIN, -1), evaluation)
        self.assertEqual(q.result(1, 0), [2147483648] * 6)
        self.assertEqual(q.result(q.MIN, -1), [2147483649] * 6)
        self.assertEqual(q.result(-7, 2), [-3, -4, -4, -1, 1, 1])
        self.assertEqual(q.result(7, -2), [-3, -4, -3, 1, -1, 1])
        self.assertEqual(q.result(-7, q.MIN), [0, 0, 1, -7, -7, 2147483641])
        for a, b in ((True, 1), (1, False), (q.MIN-1, 1), (1, q.MAX+1)):
            with self.assertRaises(ValueError): q.result(a, b)

    def test_each_group_has_all_arms_without_result_driven_order(self):
        p = q.specification()
        for group in range(p['groups']):
            self.assertEqual(set(q.order(p, group)), set(q.ARMS))
            self.assertEqual(len(q.order(p, group)), len(q.ARMS))
        self.assertEqual(q.order(p, 0), list(q.ARMS))

    def observation(self):
        rows = q.corpora()['evaluation']
        observed = {'cases': len(rows), 'samples': 3, 'repeats': 2,
            'calls': len(rows)*6*3*2,
            'checksum': (sum(sum(r['expected']) for r in rows)*3*2) % (1<<64),
            'load_ns': 30, 'first_request_ns': 10, 'cold_delivery_ns': 40,
            'peak_rss_kib': 1024, 'batch_ns': [100, 200, 300]}
        return rows, observed

    def test_observation_rejects_missing_work_wrong_result_and_fabricated_types(self):
        rows, original = self.observation()
        self.assertIs(q.validate_observation(original, rows, 3, 2), original)
        mutations = {
            'calls': 1, 'checksum': original['checksum'] ^ 1, 'samples': 2,
            'repeats': True, 'cases': 0, 'load_ns': 0, 'first_request_ns': -1,
            'cold_delivery_ns': 39, 'peak_rss_kib': -1,
            'batch_ns': [100, 200],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(original); changed[field] = value
                with self.assertRaises(ValueError): q.validate_observation(changed, rows, 3, 2)
        for times in ([100, 0, 300], [100, True, 300], [100, 200, float('nan')]):
            changed=copy.deepcopy(original); changed['batch_ns']=times
            with self.assertRaises(ValueError): q.validate_observation(changed, rows, 3, 2)

    def test_quantiles_are_nearest_rank_raw_batch_not_claimed_request_tails(self):
        self.assertEqual(q.summary(list(range(1, 101))),
            {'median_ns': 50, 'p95_ns': 95, 'p99_ns': 99})
        self.assertEqual(q.summary([9]), {'median_ns': 9, 'p95_ns': 9, 'p99_ns': 9})
        self.assertIn('not individual request p99', q.specification()['tail_scope'])


@unittest.skipUnless(shutil.which('git'), 'Git required for raw source binding')
class StbServiceSourceBindingTests(unittest.TestCase):
    def test_hidden_dirty_source_and_ignored_source_injection_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='stb-service-source-') as directory:
            root = Path(directory)
            files = ['tools/qualify_hia_stb_service.py', 'tests/test_hia_stb_service.py',
                     'tests/test_hia_stb_divide_update.py', 'tests/fixtures/c_migration/stb_divide_vm_readback.json',
                     'hepta/test_module.py', '.gitignore']
            for name in files:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('hepta/ignored.py\n' if name == '.gitignore' else 'original\n')
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', *args], cwd=root, stderr=subprocess.PIPE)
            git('init'); git('add', '.'); git('commit', '-m', 'fixture')
            head = git('rev-parse', 'HEAD').decode().strip()
            with patch.object(q, 'ROOT', root):
                q.snapshot(head)
                git('update-index', '--assume-unchanged', 'hepta/test_module.py')
                (root/'hepta/test_module.py').write_text('hidden edit\n')
                self.assertFalse(git('status', '--porcelain'))
                with self.assertRaisesRegex(ValueError, 'canonical Git blob'): q.snapshot(head)
                (root/'hepta/test_module.py').write_text('original\n')
                (root/'hepta/ignored.py').write_text('untracked code injection\n')
                self.assertFalse(git('status', '--porcelain'))
                with self.assertRaisesRegex(ValueError, 'injected source'): q.snapshot(head)
                (root/'hepta/ignored.py').unlink()
                git('config', 'core.filemode', 'false')
                (root/'hepta/test_module.py').chmod(0o755)
                with self.assertRaisesRegex(ValueError, 'executable mode'): q.snapshot(head)


@unittest.skipUnless(shutil.which('gcc') and shutil.which('g++'), 'native GCC C/C++ required')
class StbServiceNativeHarnessTests(unittest.TestCase):
    def test_unmodified_upstream_c_cpp_cover_full_eval_and_actual_wrong_result_fails(self):
        rows = q.corpora()['evaluation']
        with tempfile.TemporaryDirectory(prefix='stb-service-native-') as directory:
            d = Path(directory)
            (d/'stb_divide.h').write_bytes((q.update.SUCCESSOR/'stb_divide.h').read_bytes())
            (d/'inputs.txt').write_text(''.join(' '.join(map(str,[r['a'],r['b'],*r['expected']]))+'\n' for r in rows))
            subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(q.FIXTURES/'driver.c'),'-ldl','-o',str(d/'driver')],check=True,capture_output=True)
            for compiler, ext, standard in (('gcc','c','c11'), ('g++','cpp','c++17')):
                (d/('baseline.'+ext)).write_text(q.c_source())
                subprocess.run([compiler,'-std='+standard,'-O3','-flto','-fno-semantic-interposition','-ftrapv','-DC_INTEGER_DIVISION_TRUNCATES',
                    '-fPIC','-shared','-fsanitize=undefined','-fno-sanitize-recover=undefined',str(d/('baseline.'+ext)),'-o',str(d/'target.so')],check=True,capture_output=True)
                result=subprocess.run([str(d/'driver'),str(d/'target.so'),str(d/'inputs.txt'),'1','1'],check=True,text=True,capture_output=True)
                q.validate_observation(json.loads(result.stdout),rows,1,1)
            (d/'wrong.c').write_text('#include <stdint.h>\n'+'\n'.join(f'int64_t service_{fn}(int32_t a,int32_t b){{(void)a;(void)b;return 0;}}' for fn in q.FUNCTIONS))
            subprocess.run(['gcc','-shared','-fPIC',str(d/'wrong.c'),'-o',str(d/'wrong.so')],check=True,capture_output=True)
            result=subprocess.run([str(d/'driver'),str(d/'wrong.so'),str(d/'inputs.txt'),'1','1'],text=True,capture_output=True)
            self.assertEqual(result.returncode,8)
            self.assertIn('mismatch',result.stderr)

    def test_malformed_and_out_of_range_input_rejected_before_library_load(self):
        with tempfile.TemporaryDirectory(prefix='stb-service-input-') as directory:
            d=Path(directory)
            subprocess.run(['gcc','-std=c11','-O2',str(q.FIXTURES/'driver.c'),'-ldl','-o',str(d/'driver')],check=True,capture_output=True)
            for text in ('0 1 0\n','2147483648 1 0 0 0 0 0 0\n','garbage\n', '9999999999999999999999999999999999999 1 0 0 0 0 0 0\n', '1 1 1 1 1 1 1 1 extra\n'):
                (d/'input').write_text(text)
                result=subprocess.run([str(d/'driver'),str(d/'missing.so'),str(d/'input'),'1','1'],capture_output=True)
                self.assertIn(result.returncode,(4,5))


if __name__ == '__main__':
    unittest.main()
