"""Actual finite x86 LTO feature binding; no original-host reconstruction."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

from tools import hia_filecheck_target_profile as target


MINI_IR = '''target triple = "x86_64-unknown-linux-gnu"
define i32 @feature_probe(i64 %n) {
entry:
  %one = insertelement <4 x i64> poison, i64 %n, i32 0
  %all = shufflevector <4 x i64> %one, <4 x i64> poison, <4 x i32> zeroinitializer
  %predicate = icmp uge <4 x i64> %all, <i64 1, i64 2, i64 3, i64 4>
  %bits = bitcast <4 x i1> %predicate to i4
  %result = zext i4 %bits to i32
  ret i32 %result
}
'''
MINI_C = '''typedef unsigned long long vector4 __attribute__((ext_vector_type(4)));
unsigned int feature_probe(unsigned long long count) {
    vector4 values = (vector4){count, count, count, count};
    vector4 thresholds = (vector4){1, 2, 3, 4};
    vector4 compared = (vector4)(values >= thresholds);
    return (unsigned int)((compared[0] & 1) | (compared[1] & 2) |
                          (compared[2] & 4) | (compared[3] & 8));
}
'''
RUNNER_C = r'''
#include <cpuid.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t (*probe_fn)(uint64_t);
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    unsigned a, b, c, d, lo = 0, hi = 0;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & (1U << 27))) return 65;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 66;
    printf("{\"avx2\":%u,\"avx512f\":%u,\"avx512dq\":%u,\"avx512vl\":%u,\"xcr0\":%llu}\n",
           (b >> 5) & 1U, (b >> 16) & 1U, (b >> 17) & 1U, (b >> 31) & 1U,
           (unsigned long long)lo | ((unsigned long long)hi << 32));
    fflush(stdout);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 67; }
    void *symbol = dlsym(library, "feature_probe");
    if (!symbol) return 68;
    probe_fn fn;
    _Static_assert(sizeof(fn) == sizeof(symbol), "POSIX pointer representation");
    memcpy(&fn, &symbol, sizeof(fn));
    uint32_t result = fn(strtoull(argv[2], NULL, 10));
    printf("{\"result\":%u}\n", result);
    return dlclose(library) ? 69 : 0;
}
'''


def frontend_ir(attributes=None, group="7"):
    if attributes is None:
        attributes = ('nounwind memory(none) "target-cpu"="znver4" '
                      '"target-features"="+64bit,+avx2,+sse2,-avx512f,-avx512vl"')
    return ('target triple = "x86_64-pc-linux-gnu"\n'
            'define i64 @' + target.PROBE_NAME + '(i64 %0) #' + group + ' {\n'
            '  ret i64 %0\n}\nattributes #' + group + ' = { ' + attributes + ' }\n')


class FilecheckTargetProfileTests(unittest.TestCase):
    def test_exact_referenced_group_preserves_every_positive_and_negative_feature(self):
        source = frontend_ir() + ('attributes #0 = { "target-cpu"="generic" '
                                 '"target-features"="+avx512f,-avx2" }\n')
        parsed = target._parse_frontend_profile(source)
        self.assertEqual(parsed["target_cpu"], "znver4")
        self.assertEqual(parsed["probe_attribute_group"], "7")
        self.assertEqual(parsed["target_features"], "+64bit,+avx2,+sse2,-avx512f,-avx512vl")
        self.assertEqual(parsed["signed_features"], ["+64bit", "+avx2", "+sse2", "-avx512f", "-avx512vl"])

    def test_missing_duplicate_conflicting_or_escaped_profile_fields_are_refused(self):
        valid = frontend_ir()
        candidates = [
            valid.replace('"target-cpu"="znver4"', ''),
            valid.replace('"target-features"="+64bit,+avx2,+sse2,-avx512f,-avx512vl"', ''),
            valid.replace('"target-cpu"="znver4"', '"target-cpu"="znver4" "target-cpu"="generic"'),
            valid.replace('"target-features"=', '"target-features"="+avx512f,-sse" "target-features"='),
            valid.replace('+64bit,+avx2', '+64bit,+avx2,+avx2'),
            valid.replace('+64bit,+avx2', '+64bit,+avx2,-avx2'),
            valid.replace('-avx512f,-avx512vl', '+avx512f,+avx512vl'),
            valid.replace('+64bit,+avx2,+sse2', '-64bit,-avx2,-sse2'),
            valid.replace('znver4', 'znver4\\22'),
            valid.replace('+avx2', '+avx2\\0A'),
            valid.replace('+avx2', '+avx2,,+sse'),
            valid.replace('attributes #7 =', 'attributes #8 ='),
            valid + 'attributes ' + valid.split('attributes ', 1)[1],
            valid.replace('x86_64-pc-linux-gnu', 'aarch64-unknown-linux-gnu'),
            valid + '\n' + 'x' * target.MAX_PROBE_IR_BYTES,
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate[:160]):
                with self.assertRaisesRegex(ValueError, "E_HIA_FILECHECK_TARGET"):
                    target._parse_frontend_profile(candidate)

    def test_ambiguous_probe_definitions_or_group_spelling_are_refused(self):
        valid = frontend_ir()
        for candidate in (valid.replace('#7 {', '{'),
                          valid.replace(target.PROBE_NAME, 'unrelated_probe'),
                          valid + 'define i64 @second(i64 %v) {\n ret i64 %v\n}\n',
                          valid.replace('attributes #7 = {', 'attributes #7 = {\n')):
            with self.subTest(candidate=candidate[:160]):
                with self.assertRaisesRegex(ValueError, "E_HIA_FILECHECK_TARGET"):
                    target._parse_frontend_profile(candidate)

    def test_all_internal_and_exported_definitions_receive_the_exact_policy(self):
        profile = target._parse_frontend_profile(frontend_ir())
        source = MINI_IR + '''
define internal i64 @helper(i64 %v) {
  ret i64 %v
}
define i64 @public_entry(i64 %v) {
  %out = call i64 @helper(i64 %v)
  ret i64 %out
}
'''
        original = source
        bound, functions = target._bind_attributes(source, profile)
        self.assertEqual(source, original)
        self.assertEqual(functions, ["feature_probe", "helper", "public_entry"])
        self.assertEqual(bound.count(' #0 {'), 3)
        self.assertEqual(bound.count('attributes #0 = {'), 1)
        self.assertIn('"target-features"="' + profile["target_features"] + '"', bound)
        self.assertEqual(bound.split('\n\nattributes #0', 1)[0].replace(' #0 {', ' {').rstrip(), source.rstrip())

    def test_preexisting_or_partial_ir_bindings_are_refused(self):
        profile = target._parse_frontend_profile(frontend_ir())
        for source in (MINI_IR.replace(') {', ') #0 {'),
                       MINI_IR + 'attributes #0 = { nounwind }\n',
                       MINI_IR.replace(') {', ') "target-cpu"="generic" {'),
                       MINI_IR + 'define ' + MINI_IR.split('define ', 1)[1],
                       MINI_IR.replace('define i32', 'define\ni32'),
                       MINI_IR.replace('x86_64-unknown-linux-gnu', 'x86_64-apple-darwin')):
            with self.subTest(source=source[:160]):
                with self.assertRaisesRegex(ValueError, "E_HIA_FILECHECK_TARGET"):
                    target._bind_attributes(source, profile)

    def test_research_flags_cannot_silently_downgrade_or_add_driver_inputs(self):
        base = ['-O3', '-flto=full', '-fuse-ld=/usr/bin/ld.lld', '-march=native', '-fPIC', '-shared']
        self.assertEqual(target._frontend_flags(base), ['-O3', '-flto=full', '-march=native', '-fPIC'])
        candidates = [base + ['-O0'], [value for value in base if value != '-flto=full'],
                      base + ['-fPIC'], base + ['@override.rsp'], base + ['-o', '/tmp/other-output'],
                      [value.replace('-march=native', '-march=x86-64') for value in base],
                      base + ['-Xclang', '-target-feature', '+avx512f'], base + [True]]
        for candidate in candidates:
            with self.subTest(flags=candidate):
                with self.assertRaisesRegex(ValueError, "E_HIA_FILECHECK_TARGET"):
                    target._frontend_flags(candidate)

    def test_later_process_ledger_mutation_cannot_rewrite_the_captured_profile(self):
        clang = shutil.which(os.environ.get('CLANG', 'clang'))
        linker = shutil.which(os.environ.get('HEPTA_LLD', 'ld.lld'))
        self.assertIsNotNone(clang, 'actual Clang required')
        self.assertIsNotNone(linker, 'actual ELF LTO linker required')
        flags = ['-O3', '-flto=full', '-fuse-ld=' + linker, '-march=native', '-fPIC', '-shared']
        rows = []

        def recorded(argv, stage, *, timeout):
            process = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
            row = {'argv': argv, 'stage': stage, 'returncode': process.returncode,
                   'stdout': process.stdout, 'stderr': process.stderr}
            rows.append(row)
            self.assertEqual(process.returncode, 0, process.stderr)
            return row

        with tempfile.TemporaryDirectory(prefix='hepta-filecheck-profile-copy-') as tmp:
            output = Path(tmp) / 'profile'
            _, profile = target.bind_native_target_profile(MINI_IR, clang=clang, flags=flags,
                                                            directory=output, command=recorded)
            expected = deepcopy(profile)
            saved = json.loads((output / 'profile.json').read_bytes())
            # The qualifier's final ledger compaction removes these fields.
            # Also mutate a nested value to catch a merely shallow copy.
            rows[0].pop('stdout')
            rows[0].pop('stderr')
            rows[0]['argv'][0] = 'synthetic post-capture replacement'
            self.assertEqual(profile, expected)
            self.assertEqual(profile, saved)
            payload = {key: value for key, value in profile.items() if key != 'profile_sha256'}
            self.assertEqual(profile['profile_sha256'], sha256(target._wire(payload)).hexdigest())

    def test_masked_cpu_lto_preserves_complete_frontend_feature_policy(self):
        self.assertEqual(platform.system(), "Linux", "this is the declared Linux x86-64 research gate")
        self.assertIn(platform.machine(), {"x86_64", "AMD64"})
        tools = {}
        for label, variable, fallback in (("clang", "CLANG", "clang"),
                                          ("linker", "HEPTA_LLD", "ld.lld"),
                                          ("qemu", "HEPTA_QEMU_X86_64", "qemu-x86_64")):
            selector = os.environ.get(variable, fallback)
            found = shutil.which(selector)
            self.assertIsNotNone(found, "actual required tool missing: " + variable)
            tools[label] = str(Path(found).absolute())  # Keep ld.lld argv[0].
        commands, observations = [], {}

        with tempfile.TemporaryDirectory(prefix="hepta-filecheck-target-") as tmp:
            root = Path(tmp)

            def command(argv, stage, *, timeout=30):
                actual = list(map(str, argv))
                process = subprocess.run(actual, cwd=root, text=True, capture_output=True, timeout=timeout)
                row = {"argv": actual, "stage": stage, "returncode": process.returncode,
                       "stdout": process.stdout, "stderr": process.stderr}
                commands.append(row)
                self.assertEqual(process.returncode, 0, json.dumps(row, sort_keys=True))
                return row

            try:
                version = command([tools['clang'], '--version'], 'clang_version')
                self.assertRegex(version['stdout'], r'clang version 20\.')
                command([tools['linker'], '--version'], 'lld_version')
                command([tools['qemu'], '--version'], 'qemu_version')
                disabled = ['-mno-' + name for name in sorted(target._DISABLED_CONTROL_FEATURES)]
                flags = ['-O3', '-flto=full', '-fuse-ld=' + tools['linker'],
                         '-march=znver4', *disabled, '-fPIC', '-shared']
                bound, profile = target.bind_native_target_profile(MINI_IR, clang=tools['clang'],
                    flags=flags, directory=root / 'target-profile', command=command)
                self.assertEqual(profile['target_cpu'], 'znver4')
                self.assertIn('-avx512f', profile['signed_features'])
                self.assertNotIn('+avx512f', profile['signed_features'])
                self.assertEqual(profile['original_ir_sha256'], sha256(MINI_IR.encode()).hexdigest())
                self.assertEqual(profile['bound_ir_sha256'], sha256(bound.encode()).hexdigest())
                self.assertEqual(profile['bound_functions'], ['feature_probe'])
                self.assertFalse(profile['default_backend_receipt'])
                self.assertFalse(profile['program_admission_authority'])
                raw, fixed, c = root / 'raw.ll', root / 'bound.ll', root / 'reference.c'
                raw.write_text(MINI_IR)
                fixed.write_text(bound)
                c.write_text(MINI_C)
                paths = {}
                for label, source in (('raw', raw), ('bound', fixed), ('c', c)):
                    paths[label] = root / (label + '.so')
                    command([tools['clang'], *flags, source, '-o', paths[label]], label + '_build')
                (root / 'runner.c').write_text(RUNNER_C)
                command([tools['clang'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                         root / 'runner.c', '-ldl', '-o', root / 'runner'], 'runner_build')
                cpu = None
                for label in ('raw', 'bound', 'c'):
                    counts = [1] if label == 'raw' else [0, 1, 2, 3, 4, (1 << 64) - 1]
                    observations[label] = []
                    for count in counts:
                        argv = [tools['qemu'], '-cpu', 'Haswell-v4', str(root / 'runner'), str(paths[label]), str(count)]
                        process = subprocess.run(argv, cwd=root, text=True, capture_output=True, timeout=30)
                        row = {'argv': argv, 'count': count, 'returncode': process.returncode,
                               'stdout': process.stdout, 'stderr': process.stderr}
                        observations[label].append(row)
                        output = [json.loads(line) for line in process.stdout.splitlines()]
                        self.assertTrue(output, json.dumps(row, sort_keys=True))
                        actual_cpu = output[0]
                        self.assertEqual({key: actual_cpu[key] for key in ('avx2', 'avx512f', 'avx512dq', 'avx512vl')},
                                         {'avx2': 1, 'avx512f': 0, 'avx512dq': 0, 'avx512vl': 0})
                        self.assertEqual(actual_cpu['xcr0'], 7)
                        if cpu is None:
                            cpu = actual_cpu
                        self.assertEqual(actual_cpu, cpu)
                        if label == 'raw':
                            self.assertEqual(process.returncode, -signal.SIGILL, json.dumps(row, sort_keys=True))
                        else:
                            self.assertEqual(process.returncode, 0, json.dumps(row, sort_keys=True))
                            self.assertEqual(output[1], {'result': (1 << min(count, 4)) - 1})
                self.assertEqual(MINI_IR, raw.read_text())
                observations['cpu'] = cpu
                observations['profile_sha256'] = profile['profile_sha256']
                observations['binary_identities'] = {name: sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
                observations['original_ci_host_features_reconstructed'] = False
            finally:
                payload = {'schema': 'hepta.filecheck-target-profile-regression.v1',
                           'observations': observations, 'commands': commands}
                (root / 'execution.json').write_text(json.dumps(payload, sort_keys=True, indent=2) + '\n')
                retained = os.environ.get('HEPTA_FILECHECK_TARGET_EVIDENCE')
                if retained:
                    destination = Path(retained) / 'masked-cpu-lto'
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(root, destination)
                # Keep the measured negative control in ordinary suite logs too.
                print(json.dumps({'filecheck_target_profile_execution': payload}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
