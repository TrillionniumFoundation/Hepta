"""Actual host observations and fail-closed hardware/OS feature admission."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_verified_cpu import (VerifiedCPURejected, decode_cpu_features,
                                  probe_host_isa, require_host_isa, resolve_target_isa)


def raw_cpu(**changes):
    result = dict(max_basic=7, leaf1_ecx=0x1c000000, xcr0_lo=0xe6, xcr0_hi=0,
                  leaf7_ebx=(1 << 5) | (1 << 16) | (1 << 17) | (1 << 30) | (1 << 31))
    result.update(changes)
    return result


class VerifiedCPUAdmissionTests(unittest.TestCase):
    def test_avx_requires_hardware_xsave_osxsave_and_avx(self):
        for bit in (26, 27, 28):
            with self.subTest(bit=bit):
                features, _ = decode_cpu_features(raw_cpu(leaf1_ecx=0x1c000000 & ~(1 << bit)))
                self.assertEqual(features, ['sse2'])

    def test_os_must_enable_each_vector_state_component(self):
        for bit in (1, 2):
            with self.subTest(bit=bit):
                self.assertEqual(decode_cpu_features(raw_cpu(xcr0_lo=0xe6 & ~(1 << bit)))[0], ['sse2'])
        for bit in (5, 6, 7):
            with self.subTest(bit=bit):
                self.assertEqual(decode_cpu_features(raw_cpu(xcr0_lo=0xe6 & ~(1 << bit)))[0],
                                 ['avx', 'avx2', 'sse2'])

    def test_each_extension_bit_is_required_independently(self):
        for name, bit in (('avx2', 5), ('avx512dq', 17), ('avx512bw', 30), ('avx512vl', 31)):
            with self.subTest(name=name):
                source = raw_cpu()
                source['leaf7_ebx'] &= ~(1 << bit)
                self.assertNotIn(name, decode_cpu_features(source)[0])
        source = raw_cpu()
        source['leaf7_ebx'] &= ~(1 << 16)
        self.assertEqual(decode_cpu_features(source)[0], ['avx', 'avx2', 'sse2'])

    def test_unavailable_cpuid_leaves_cannot_grant_extensions(self):
        self.assertEqual(decode_cpu_features(raw_cpu(max_basic=0))[0], ['sse2'])
        self.assertEqual(decode_cpu_features(raw_cpu(max_basic=1))[0], ['avx', 'sse2'])

    def test_malformed_raw_observations_are_rejected(self):
        invalid = [None, [], {}, {**raw_cpu(), 'extra': 1}]
        invalid += [raw_cpu(leaf7_ebx=value) for value in (True, -1, 1 << 32, 1.0, '32')]
        for observation in invalid:
            with self.subTest(observation=observation), self.assertRaises(VerifiedCPURejected):
                decode_cpu_features(observation)

    def test_live_probe_covers_affinity_and_does_not_change_caller(self):
        original = os.sched_getaffinity(0)
        observed = probe_host_isa()
        self.assertEqual(os.sched_getaffinity(0), original)
        self.assertEqual(observed['affinity'], sorted(original))
        self.assertEqual([r['cpu'] for r in observed['cpus']], sorted(original))
        common = set(decode_cpu_features(observed['cpus'][0]['raw'])[0])
        for row in observed['cpus']:
            common &= set(decode_cpu_features(row['raw'])[0])
        self.assertEqual(observed['common_features'], sorted(common))

    def test_baseline_c_cpuid_oracle_agrees_on_one_pinned_cpu(self):
        # This separately compiled C control uses GCC's cpuid.h and explicit
        # XGETBV. It neither consumes the Python decoder nor copies probe bytes.
        source = r'''
#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
int main(void) {
    unsigned int a=0,b=0,c=0,d=0,ecx=0,lo=0,hi=0,seven=0;
    unsigned int maximum=__get_cpuid_max(0,0);
    if (maximum>=1) {
        __cpuid_count(1,0,a,b,c,d); ecx=c;
        if (ecx & (1u<<27)) __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    }
    if (maximum>=7) { __cpuid_count(7,0,a,b,c,d); seven=b; }
    printf("%u %u %u %u %u\n",maximum,ecx,lo,hi,seven);
    return 0;
}
'''
        original = os.sched_getaffinity(0)
        with tempfile.TemporaryDirectory(prefix='hia-cpu-oracle-') as name:
            root = Path(name)
            (root / 'probe.c').write_text(source)
            subprocess.run(['cc', '-O2', '-march=x86-64', '-mno-avx', str(root / 'probe.c'),
                            '-o', str(root / 'probe')], check=True, capture_output=True, timeout=30)
            try:
                os.sched_setaffinity(0, {min(original)})
                expected = list(map(int, subprocess.check_output([str(root / 'probe')], timeout=10).split()))
                observed = probe_host_isa()['cpus'][0]['raw']
                self.assertEqual([observed[k] for k in
                    ('max_basic', 'leaf1_ecx', 'xcr0_lo', 'xcr0_hi', 'leaf7_ebx')], expected)
            finally:
                os.sched_setaffinity(0, original)

    def test_probe_fault_and_malformed_output_fail_closed(self):
        for result in (SimpleNamespace(returncode=-4, stdout='', stderr='SIGILL'),
                       SimpleNamespace(returncode=0, stdout='not JSON', stderr=''),
                       SimpleNamespace(returncode=0, stdout='{}', stderr='')):
            with self.subTest(result=result), patch('hepta.clang_capture.run_bounded', return_value=result), \
                    self.assertRaises(VerifiedCPURejected):
                probe_host_isa()

    def test_execution_admission_always_probes_again(self):
        first = {'common_features': ['avx', 'avx2', 'sse2'], 'common_xcr0': 6}
        second = {'common_features': ['sse2'], 'common_xcr0': 0}
        with patch('hepta.hia_verified_cpu.probe_host_isa', side_effect=[first, second]) as probe:
            self.assertIs(require_host_isa(['avx', 'avx2'], 6), first)
            with self.assertRaises(VerifiedCPURejected):
                require_host_isa(['avx', 'avx2'], 6)
            self.assertEqual(probe.call_count, 2)
        with self.assertRaises(TypeError):
            require_host_isa(['avx2'], 6, observation=first)

    def test_unknown_requirements_cannot_be_silently_ignored(self):
        for features, mask in ((['avx1024'], 6), ('avx2', 6), (['avx2'], True), (['avx2'], 7)):
            with self.subTest(features=features, mask=mask), self.assertRaises(VerifiedCPURejected):
                require_host_isa(features, mask)

    def test_native_selection_uses_common_enabled_features(self):
        for features, expected in ((['sse2'], 'sse2'), (['sse2', 'avx', 'avx2'], 'avx2'),
            (['sse2', 'avx', 'avx2', 'avx512f'], 'avx2'),
            (['sse2', 'avx', 'avx2', 'avx512f', 'avx512bw'], 'avx512')):
            with self.subTest(expected=expected), patch('hepta.hia_verified_cpu.probe_host_isa',
                    return_value={'common_features': features}):
                self.assertEqual(resolve_target_isa('native'), expected)


if __name__ == '__main__':
    unittest.main()
