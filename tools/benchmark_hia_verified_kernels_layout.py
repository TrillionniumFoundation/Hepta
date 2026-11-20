"""Run the complete two-phase v7 layout campaign, preserving every v6 case.

Phase one calls the unchanged v6 runner into its own retained evidence tree.
Phase two uses exactly those libraries for every predeclared layout. Neither
phase can be selected or resumed through this tool. --plan-only executes no
build, driver, proof or timing workload. The driver separately supports
--validate-only for untimed functional regression tests.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = 'benchmarks/hia_verified_kernels/PROTOCOL_LAYOUT_V7.json'
LEGACY_SCRIPT = 'tools/benchmark_hia_verified_kernels.py'
LEGACY_PROTOCOL_SHA = '08e0cfb3c5790120ad24dc22fe93e9426fe22a6432b4637bf1673da043b6be1f'
LEGACY_SCRIPT_SHA = '261fc80917b1fe109b1b424150806705b9e27c7f54eb1d1be19e331dfbd244b7'
LEGACY_DRIVER_SHA = 'd3a19775fe32845e3cd2eeaee52a8346415835d4adb796b06ac8fe99006a6626'
LENGTHS = [0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
           255, 256, 257, 4095, 4096, 4097, 65535, 65536]
MASK = (1 << 64) - 1
SEED = 0x123456789abcdef


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def original_inventory():
    cases = [('scalar', arm, 0) for arm in ('scalar-direct', 'scalar-verified', 'c', 'rust')]
    for mode in ('sum', 'zero', 'copy'):
        for length in LENGTHS:
            arms = ['verified-sse2-64', 'verified-sse2-16', 'verified-avx2-128', 'verified-avx512-256']
            if mode == 'copy':
                arms += ['verified-avx2-copy-byte-tail', 'verified-avx512-copy-byte-tail']
            arms += ['verified-' + isa + ('-copy-endpoints-fast' if mode == 'copy' else '-bounded-tail')
                     for isa in ('avx2', 'avx512')]
            if mode != 'copy':
                arms += ['verified-avx2-bounded-one', 'verified-avx512-bounded-one']
            cases += [(mode, arm, length) for arm in arms + ['direct-packed-u32', 'c', 'rust']]
    require(len(cases) == len(set(cases)) == 763, 'original v6 inventory differs')
    return cases


def controlled_inventory():
    cases = []
    for mode, arm, length in original_inventory():
        if mode == 'scalar':
            continue
        layouts = [(gap, order) for gap in (131072, 131136) for order in ('src-low', 'src-high')]
        if mode != 'copy':
            layouts = [(131072, 'src-low')]
        for gap, order in layouts:
            layout = 'phase0-reduction' if mode != 'copy' else f'phase0-gap{gap}-{order}'
            cases.append({'mode': mode, 'arm': arm, 'length': length,
                          'layout': layout, 'gap': gap, 'address_order': order})
    require(len(cases) == 1518 and sum(c['mode'] == 'copy' for c in cases) == 1012,
            'complete controlled layout inventory differs')
    random.Random(20261119).shuffle(cases)
    return cases


def read_protocol(root):
    protocol = json.loads((root / PROTOCOL).read_text())
    old = json.loads((root / 'benchmarks/hia_verified_kernels/PROTOCOL.json').read_text())
    require(protocol['schema'] == 'hepta.hia.verified-kernel-microbench.v7.layout', 'v7 layout protocol required')
    require(protocol['cases'] == 2281 and protocol['samples'] == 47901 and
            protocol['controlled_cases'] == 1518 and protocol['controlled_samples'] == 31878 and
            protocol['controlled_copy_cases'] == 1012 and protocol['controlled_reduction_cases'] == 506,
            'v7 complete inventory counts differ')
    require(protocol['lengths'] == old['lengths'] == LENGTHS and
            protocol['span_iterations'] == old['span_iterations'] and
            protocol['samples_per_case'] == 21 and protocol['warmup_batches'] == 3,
            'original lengths, iterations or sample counts changed')
    expected_legacy = {'path': 'benchmarks/hia_verified_kernels/PROTOCOL.json',
                       'schema': 'hepta.hia.verified-kernel-microbench.v6',
                       'sha256': LEGACY_PROTOCOL_SHA, 'cases': 763, 'samples': 16023,
                       'benchmark_sha256': LEGACY_SCRIPT_SHA, 'driver_sha256': LEGACY_DRIVER_SHA}
    require(protocol['legacy_protocol'] == expected_legacy, 'historical v6 control identities changed')
    for relative, expected in ((expected_legacy['path'], LEGACY_PROTOCOL_SHA),
                               (LEGACY_SCRIPT, LEGACY_SCRIPT_SHA),
                               ('benchmarks/hia_verified_kernels/driver.c', LEGACY_DRIVER_SHA)):
        require(digest(root / relative) == expected, 'original control source bytes changed: ' + relative)
    layout = protocol['layout']
    require(layout['profile'] == 'hia.kernel-layout.phase0.v1' and layout['arena_bytes'] == 262144 and
            layout['page_bytes'] == 4096 and layout['lower_offset'] == 4096 and layout['lower_base_phase'] == 0 and
            layout['copy_gaps'] == [131072, 131136] and layout['copy_orders'] == ['src-low', 'src-high'] and
            layout['reduction_gap'] == 131072 and layout['reduction_order'] == 'src-low' and
            layout['relative_offsets'] == [1, 16] and layout['offset_expression'] == '1 + (iteration & 15)',
            'controlled arena conditions differ')
    driver = protocol['controlled_driver']
    require(driver['path'] == 'benchmarks/hia_verified_kernels/driver_layout.c' and
            driver['compiler_flags'] == ['-O3', '-std=c11'] and driver['link_flags'] == ['-ldl'] and
            driver['sha256'] == digest(root / driver['path']), 'controlled driver source or flags differ')
    require(protocol['order']['seed'] == 20261119, 'fixed layout shuffle seed changed')
    return protocol


@lru_cache(maxsize=None)
def checksum(mode, length, calls):
    if mode == 'copy':
        return (SEED + length * calls) & MASK
    if mode == 'zero':
        return (SEED + calls) & MASK
    state, source = 0x3c79ac492ba7b653, bytearray()
    for _ in range(length + 32):
        state ^= state >> 12
        state ^= (state << 25) & MASK
        state ^= state >> 27
        source.append(((state * 0x2545f4914f6cdd1d) & MASK) >> 56)
    return (SEED + sum(sum(source[offset:offset + length]) *
                       (calls // 16 + (offset <= calls % 16)) for offset in range(1, 17))) & MASK


def validate_samples(case, metadata, samples, calls):
    require(metadata['record'] == 'layout' and metadata['schema'] == 'hia.kernel-layout.phase0.v1' and
            metadata['arena_allocated_before_dlopen'] is True and metadata['validation_only'] is False,
            'controlled driver did not record a timing layout')
    for name in ('mode', 'length', 'gap', 'address_order'):
        require(metadata[name] == case[name], 'actual driver layout differs: ' + name)
    require(metadata['arena_bytes'] == 262144 and metadata['page_bytes'] == 4096 and
            metadata['relative_offsets'] == [1, 16], 'arena or relative offsets differ')
    arena, lower, upper = (metadata[k] for k in ('arena_base', 'lower_base', 'upper_base'))
    require(all(type(x) is int and x > 0 for x in (arena, lower, upper)) and arena % 4096 == 0 and
            lower == arena + 4096 and upper == lower + case['gap'] and
            upper + 65536 + 32 <= arena + 262144, 'actual arena allocation relationship differs')
    src, dst = (upper, lower) if case['address_order'] == 'src-high' else (lower, upper)
    require(metadata['source_base'] == src and metadata['destination_base'] == dst and
            metadata['destination_minus_source'] == dst - src and
            metadata['source_mod64'] == src % 64 and metadata['destination_mod64'] == dst % 64 and
            metadata['source_mod4096'] == src % 4096 and metadata['destination_mod4096'] == dst % 4096,
            'actual pointer phases, order or signed distance differ')
    require(len(samples) == 21 and [s['batch'] for s in samples] == list(range(21)), 'incomplete layout batches')
    expected = checksum(case['mode'], case['length'], calls)
    for sample in samples:
        require(type(sample['calls']) is int and sample['calls'] == calls and
                type(sample['elapsed_ns']) is int and sample['elapsed_ns'] > 0 and
                math.isfinite(sample['ns_per_call']) and
                abs(sample['ns_per_call'] - sample['elapsed_ns'] / calls) <= 5.1e-10 and
                sample['checksum'] == expected and sample['source_base'] == src and sample['destination_base'] == dst,
                'invalid checksum, timing division or changed batch addresses')


def benchmark(output, *, cpu, cc='gcc', rustc='rustc'):
    protocol = read_protocol(ROOT)
    destination = Path(output).absolute()
    destination.mkdir(parents=False, exist_ok=False)
    record = {'schema': protocol['schema'], 'status': 'running', 'ok': False,
              'protocol': protocol, 'protocol_sha256': digest(ROOT / PROTOCOL),
              'started_utc': datetime.now(timezone.utc).isoformat(), 'commands': [], 'rows': [],
              'source_identity': {name: digest(ROOT / name) for name in
                  (PROTOCOL, LEGACY_SCRIPT, 'tools/benchmark_hia_verified_kernels_layout.py',
                   'benchmarks/hia_verified_kernels/driver_layout.c')},
              'scope': 'complete original v6 phase followed by complete controlled-layout phase'}
    (destination / 'protocol-layout.json').write_bytes((ROOT / PROTOCOL).read_bytes())
    tick = time.monotonic()

    def save():
        (destination / 'RESULT.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')

    def run(argv, label, timeout=120):
        start = time.monotonic()
        try:
            result = subprocess.run([str(word) for word in argv], cwd=ROOT, capture_output=True, timeout=timeout)
            stdout, stderr, returncode, timed_out = result.stdout, result.stderr, result.returncode, False
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, returncode, timed_out = exc.stdout or b'', exc.stderr or b'', None, True
        (destination / (label + '.stdout')).write_bytes(stdout)
        (destination / (label + '.stderr')).write_bytes(stderr)
        record['commands'].append({'argv': [str(word) for word in argv], 'label': label,
                                   'returncode': returncode, 'timed_out': timed_out,
                                   'elapsed_seconds': time.monotonic() - start,
                                   'stdout_sha256': sha256(stdout).hexdigest(), 'stderr_sha256': sha256(stderr).hexdigest()})
        save()
        require(returncode == 0 and not timed_out, 'layout campaign command failed: ' + label)
        return stdout.decode()

    save()
    try:
        # Import only when starting the full campaign, never for plan/readback.
        sys.path.insert(0, str(ROOT))
        spec = importlib.util.spec_from_file_location('hia_v7_unchanged_v6_runner', ROOT / LEGACY_SCRIPT)
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        original = destination / 'original-v6'
        v6 = legacy.benchmark(original, cpu=cpu, cc=cc, rustc=rustc)
        record['legacy_campaign'] = {'path': 'original-v6/RESULT.json', 'sha256': digest(original / 'RESULT.json'),
                                     'ok': v6['ok'], 'cases': len(v6['rows']), 'source_commit': v6.get('source_commit')}
        require(v6['ok'] is True and v6['status'] == 'completed', 'complete original v6 phase failed')
        ordered = original_inventory()
        random.Random(20261119).shuffle(ordered)
        require([(r['mode'], r['arm'], r['length']) for r in v6['rows']] == ordered, 'original complete case order changed')
        record['source_commit'] = v6['source_commit']
        record['host'] = v6['host']
        record['rows'] = [dict(row, phase='legacy-v6', layout=None) for row in v6['rows']]
        record['toolchain'] = v6['toolchain']
        record['runtime_dependency'] = v6['runtime_dependency']
        record['case_order'] = [dict(mode=m, arm=a, length=n, phase='legacy-v6', layout=None) for m, a, n in ordered]
        controlled = controlled_inventory()
        record['case_order'] += [dict(case, phase='controlled-layout') for case in controlled]
        originals = {(r['mode'], r['arm'], r['length']): r for r in v6['rows']}
        require(os.sched_getaffinity(0) == {cpu} == set(v6['host']['actual_affinity']), 'campaign affinity changed')
        record['layout_affinity_before'] = sorted(os.sched_getaffinity(0))
        require(run(['git', 'rev-parse', 'HEAD'], 'layout-source-commit-before', 10).strip() == v6['source_commit'] and
                not run(['git', 'status', '--porcelain=v1', '--untracked-files=no'], 'layout-source-status-before', 10).strip(),
                'source changed between complete phases')
        compiler = Path(v6['toolchain']['cc']['path'])
        require(digest(compiler) == v6['toolchain']['cc']['sha256'], 'C compiler changed between phases')
        driver = destination / 'driver-layout'
        run([compiler, '-O3', '-std=c11', ROOT / protocol['controlled_driver']['path'], '-ldl', '-o', driver], 'layout-build-driver')
        record['binaries'] = {'driver-layout': {'sha256': digest(driver), 'bytes': driver.stat().st_size}}
        run(['objdump', '-d', driver], 'layout-disassembly-driver')
        runtime = run([original / 'runtime-identity'], 'layout-runtime-identity-before').splitlines()
        require(runtime == (original / 'runtime-identity-after.stdout').read_text().splitlines(), 'runtime binding changed between phases')
        for name, binary in v6['binaries'].items():
            require(digest(original / name) == binary['sha256'], 'original built binary changed before layout phase')
        for index, case in enumerate(controlled):
            row = originals[case['mode'], case['arm'], case['length']]
            calls = protocol['span_iterations'][str(case['length'])]
            label = f"layout-case-{index:04d}-{case['mode']}-{case['arm']}-{case['length']}-{case['layout']}"
            raw = run([driver, case['mode'], original / row['library'], row['symbol'], 21, calls,
                       case['length'], case['gap'], case['address_order']], label)
            records = [json.loads(line) for line in raw.splitlines()]
            require(len(records) == 22, 'missing layout metadata or sample rows')
            metadata, samples = records[0], records[1:]
            require(metadata['cpu'] == cpu, 'actual controlled driver CPU differs')
            validate_samples(case, metadata, samples, calls)
            record['rows'].append(dict(case, phase='controlled-layout', library=row['library'], symbol=row['symbol'],
                                      layout_observation=metadata, samples=samples,
                                      median_ns_per_call=statistics.median(s['ns_per_call'] for s in samples),
                                      max_ns_per_call=max(s['ns_per_call'] for s in samples)))
            save()
        require(run(['git', 'rev-parse', 'HEAD'], 'layout-source-commit-after', 10).strip() == v6['source_commit'] and
                not run(['git', 'status', '--porcelain=v1', '--untracked-files=no'], 'layout-source-status-after', 10).strip(),
                'source changed during layout phase')
        require(run([original / 'runtime-identity'], 'layout-runtime-identity-after').splitlines() == runtime,
                'runtime IFUNC changed during layout phase')
        require(digest(Path(v6['runtime_dependency']['libc_path'])) == v6['runtime_dependency']['libc_sha256'] and
                digest(compiler) == v6['toolchain']['cc']['sha256'], 'runtime/compiler bytes changed during layout phase')
        for name, binary in v6['binaries'].items():
            require(digest(original / name) == binary['sha256'], 'same-build library or driver changed during layout phase')
        require(digest(driver) == record['binaries']['driver-layout']['sha256'], 'controlled driver changed during timing')
        record['layout_affinity_after'] = sorted(os.sched_getaffinity(0))
        require(record['layout_affinity_after'] == record['layout_affinity_before'] == [cpu], 'layout phase affinity changed')
        require(digest(original / 'RESULT.json') == record['legacy_campaign']['sha256'], 'original v6 record was modified')
        for name, expected in record['source_identity'].items():
            require(digest(ROOT / name) == expected, 'layout source changed during campaign')
        require(len(record['rows']) == 2281 and sum(len(r['samples']) for r in record['rows']) == 47901,
                'complete two-phase inventory did not finish')
        record.update(ok=True, status='completed')
    except Exception as exc:
        record.update(status='failed', error={'type': type(exc).__name__, 'message': str(exc)})
    finally:
        record.update(completed_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic() - tick)
        save()
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output')
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    if args.plan_only:
        protocol = read_protocol(ROOT)
        print(json.dumps({'ok': True, 'scope': 'inventory only; no native or proof execution',
                          'original_cases': 763, 'controlled_cases': len(controlled_inventory()),
                          'cases': protocol['cases'], 'samples': protocol['samples'],
                          'protocol_sha256': digest(ROOT / PROTOCOL)}, sort_keys=True))
        return 0
    parser.error('--output and --cpu are required for a complete run') if args.output is None or args.cpu is None else None
    result = benchmark(args.output, cpu=args.cpu, cc=args.cc, rustc=args.rustc)
    print(json.dumps({'ok': result['ok'], 'status': result['status'], 'cases': len(result['rows']),
                      'output': str(Path(args.output).absolute()), 'error': result.get('error')}, sort_keys=True))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
