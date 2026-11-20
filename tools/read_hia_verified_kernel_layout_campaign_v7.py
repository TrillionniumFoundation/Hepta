"""Independently read all original files in a complete two-phase v7 campaign.

The unchanged v6 phase goes through its own strict reader, including the old
671 controls and new loaded solver identity. This reader independently checks
all 1,518 layout cases, original driver outputs, actual addresses and the
same-build library bindings. It never executes a benchmark or reruns proof.
Raw readback requires the original compiler/runtime/solver files on the host.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import math
from pathlib import Path
import random
import statistics
import sys

PROTOCOL_PATH = 'benchmarks/hia_verified_kernels/PROTOCOL_LAYOUT_V7.json'
V6_PROTOCOL_SHA = '08e0cfb3c5790120ad24dc22fe93e9426fe22a6432b4637bf1673da043b6be1f'
V6_SCRIPT_SHA = '261fc80917b1fe109b1b424150806705b9e27c7f54eb1d1be19e331dfbd244b7'
V6_DRIVER_SHA = 'd3a19775fe32845e3cd2eeaee52a8346415835d4adb796b06ac8fe99006a6626'
MASK = (1 << 64) - 1
SEED = 0x123456789abcdef


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def independent_layout_inventory(v6_reader, original_protocol):
    cases = []
    for mode, arm, length in v6_reader.expected_cases(original_protocol):
        if mode == 'scalar':
            continue
        if mode == 'copy':
            for gap in (131072, 131136):
                for order in ('src-low', 'src-high'):
                    cases.append({'mode': mode, 'arm': arm, 'length': length,
                                  'layout': 'phase0-gap' + str(gap) + '-' + order,
                                  'gap': gap, 'address_order': order})
        else:
            cases.append({'mode': mode, 'arm': arm, 'length': length, 'layout': 'phase0-reduction',
                          'gap': 131072, 'address_order': 'src-low'})
    require(len(cases) == 1518 and len({tuple(sorted(c.items())) for c in cases}) == 1518,
            'independent controlled inventory differs')
    random.Random(20261119).shuffle(cases)
    return cases


def audit_protocol(root, original_protocol):
    protocol = json.loads((root / PROTOCOL_PATH).read_text())
    require(protocol['schema'] == 'hepta.hia.verified-kernel-microbench.v7.layout' and
            (protocol['cases'], protocol['samples'], protocol['controlled_cases'], protocol['controlled_samples'],
             protocol['controlled_reduction_cases'], protocol['controlled_copy_cases']) == (2281, 47901, 1518, 31878, 506, 1012),
            'complete v7 protocol inventory differs')
    require(protocol['lengths'] == original_protocol['lengths'] and
            protocol['span_iterations'] == original_protocol['span_iterations'] and
            protocol['samples_per_case'] == 21 and protocol['warmup_batches'] == 3 and
            protocol['clock'] == 'CLOCK_MONOTONIC_RAW' and protocol['order']['seed'] == 20261119,
            'original workload or timing conditions changed')
    expected_legacy = {'path': 'benchmarks/hia_verified_kernels/PROTOCOL.json',
                       'schema': 'hepta.hia.verified-kernel-microbench.v6', 'sha256': V6_PROTOCOL_SHA,
                       'cases': 763, 'samples': 16023, 'benchmark_sha256': V6_SCRIPT_SHA, 'driver_sha256': V6_DRIVER_SHA}
    require(protocol['legacy_protocol'] == expected_legacy, 'original v6 identity declaration changed')
    for name, expected in ((expected_legacy['path'], V6_PROTOCOL_SHA),
                           ('tools/benchmark_hia_verified_kernels.py', V6_SCRIPT_SHA),
                           ('benchmarks/hia_verified_kernels/driver.c', V6_DRIVER_SHA)):
        require(digest(root / name) == expected, 'original v6 bytes changed: ' + name)
    layout = protocol['layout']
    fixed = {'profile': 'hia.kernel-layout.phase0.v1', 'arena_bytes': 262144, 'page_bytes': 4096,
             'lower_offset': 4096, 'lower_base_phase': 0, 'copy_gaps': [131072, 131136],
             'copy_orders': ['src-low', 'src-high'], 'reduction_gap': 131072, 'reduction_order': 'src-low',
             'relative_offsets': [1, 16], 'offset_expression': '1 + (iteration & 15)'}
    require(all(layout.get(name) == expected for name, expected in fixed.items()), 'fixed layout conditions changed')
    driver = protocol['controlled_driver']
    require(driver['path'] == 'benchmarks/hia_verified_kernels/driver_layout.c' and
            driver['sha256'] == digest(root / driver['path']) and driver['compiler_flags'] == ['-O3', '-std=c11'] and
            driver['link_flags'] == ['-ldl'], 'controlled driver source or compiler flags changed')
    return protocol


def validate_observation(observed, case, affinity):
    require(observed['record'] == 'layout' and observed['schema'] == 'hia.kernel-layout.phase0.v1' and
            observed['arena_allocated_before_dlopen'] is True and observed['validation_only'] is False,
            'missing controlled timing-layout observation')
    require(observed['mode'] == case['mode'] and observed['length'] == case['length'] and
            observed['gap'] == case['gap'] and observed['address_order'] == case['address_order'],
            'observed workload/gap/order differs')
    require(type(observed['cpu']) is int and affinity == [observed['cpu']], 'controlled driver CPU differs')
    require(observed['arena_bytes'] == 262144 and observed['page_bytes'] == 4096 and
            observed['relative_offsets'] == [1, 16], 'arena extent or offset cycle differs')
    for field in ('arena_base', 'lower_base', 'upper_base', 'source_base', 'destination_base',
                  'source_mod64', 'destination_mod64', 'source_mod4096', 'destination_mod4096',
                  'destination_minus_source'):
        require(type(observed[field]) is int, 'noninteger address observation: ' + field)
    arena, low, high = observed['arena_base'], observed['lower_base'], observed['upper_base']
    require(0 < arena and arena + 262144 <= 1 << 64 and arena % 4096 == 0 and low == arena + 4096 and
            high == low + case['gap'] and high + 65536 + 32 <= arena + 262144,
            'arena bounds, phase or fixed distance differs')
    expected_src = high if case['address_order'] == 'src-high' else low
    expected_dst = low if case['address_order'] == 'src-high' else high
    require(observed['source_base'] == expected_src and observed['destination_base'] == expected_dst and
            observed['destination_minus_source'] == expected_dst - expected_src and
            abs(expected_dst - expected_src) > 65536 + 32,
            'actual source/destination order or nonoverlap differs')
    for prefix, address in (('source', expected_src), ('destination', expected_dst)):
        require(observed[prefix + '_mod64'] == address % 64 and
                observed[prefix + '_mod4096'] == address % 4096, 'actual alignment phase differs')
    return expected_src, expected_dst


def independent_checksums(protocol):
    state, prefix = 0x3c79ac492ba7b653, [0]
    for _ in range(max(protocol['lengths']) + 32):
        state ^= state >> 12
        state = (state ^ (state << 25)) & MASK
        state ^= state >> 27
        prefix.append(prefix[-1] + ((state * 0x2545f4914f6cdd1d) & MASK) // (1 << 56))
    expected = {}
    for length in protocol['lengths']:
        calls = protocol['span_iterations'][str(length)]
        expected['sum', length] = (SEED + sum((prefix[offset + length] - prefix[offset]) *
                                             (calls // 16 + int(offset <= calls % 16))
                                             for offset in range(1, 17))) & MASK
        expected['zero', length] = (SEED + calls) & MASK
        expected['copy', length] = (SEED + calls * length) & MASK
    return expected


def readback(root, path, v6_reader, previous, original_protocol, profiles, *, expected_commit=None, solver_library=None):
    protocol = audit_protocol(root, original_protocol)
    evidence = path.parent
    result = json.loads(path.read_text())
    require(result['schema'] == protocol['schema'] and result['ok'] is True and
            result['status'] == 'completed' and result['protocol'] == protocol and
            result['protocol_sha256'] == digest(root / PROTOCOL_PATH) == digest(evidence / 'protocol-layout.json'),
            'layout campaign not complete or protocol bytes differ')
    original = evidence / 'original-v6'
    binding = result['legacy_campaign']
    require(binding['path'] == 'original-v6/RESULT.json' and binding['ok'] is True and binding['cases'] == 763 and
            binding['sha256'] == digest(original / 'RESULT.json'), 'original complete v6 record binding differs')
    legacy = json.loads((original / 'RESULT.json').read_text())
    require(isinstance(legacy.get('builds'), dict) and 'wide_builds' not in legacy,
            'v7 original-file readback requires the raw v6 report, not a public projection')
    checked_v6 = v6_reader.readback(root, original / 'RESULT.json', previous, original_protocol, profiles,
                                  expected_commit=expected_commit, solver_library=solver_library)
    require(checked_v6['scope'] == 'original_files_and_record_readback' and
            checked_v6['original_command_output_binary_and_query_bytes_checked'] is True and
            checked_v6['solver_original_source_library_files_checked'] is True,
            'v6 reader did not check the original command, binary, query and solver files')
    require(result['source_commit'] == binding['source_commit'] == legacy['source_commit'], 'source commit differs across phases')
    required_sources = {PROTOCOL_PATH, 'tools/benchmark_hia_verified_kernels.py',
                        'tools/benchmark_hia_verified_kernels_layout.py', 'benchmarks/hia_verified_kernels/driver_layout.c'}
    require(set(result['source_identity']) == required_sources, 'layout source identity inventory differs')
    for name, expected in result['source_identity'].items():
        require(digest(root / name) == expected, 'layout source hash differs: ' + name)
    require(result['toolchain'] == legacy['toolchain'] and result['runtime_dependency'] == legacy['runtime_dependency'] and
            result['host'] == legacy['host'], 'same-campaign host, toolchain or runtime binding changed')
    affinity = legacy['host']['actual_affinity']
    require(result['layout_affinity_before'] == result['layout_affinity_after'] == affinity and len(affinity) == 1,
            'layout phase CPU affinity changed')
    controlled = independent_layout_inventory(v6_reader, original_protocol)
    old_rows = [dict(row, phase='legacy-v6', layout=None) for row in legacy['rows']]
    require(result['rows'][:763] == old_rows and len(result['rows']) == 2281,
            'original rows changed, discarded or combined inventory incomplete')
    expected_order = [dict(row, phase='legacy-v6', layout=None) for row in legacy['case_order']]
    expected_order += [dict(case, phase='controlled-layout') for case in controlled]
    require(result['case_order'] == expected_order, 'complete two-phase ordering differs')
    commands = result['commands']
    labels = [c['label'] for c in commands]
    prefix = ['layout-source-commit-before', 'layout-source-status-before', 'layout-build-driver',
              'layout-disassembly-driver', 'layout-runtime-identity-before']
    suffix = ['layout-source-commit-after', 'layout-source-status-after', 'layout-runtime-identity-after']
    expected_labels = prefix + [f"layout-case-{i:04d}-{c['mode']}-{c['arm']}-{c['length']}-{c['layout']}"
                                for i, c in enumerate(controlled)] + suffix
    require(len(labels) == len(set(labels)) == 1526 and labels == expected_labels,
            'v7 requires the exact sequence of all 1518 layout calls and eight fixed command receipts')
    by_label = {c['label']: c for c in commands}
    for command in commands:
        require(command['returncode'] == 0 and command['timed_out'] is False, 'failed layout command')
        for stream in ('stdout', 'stderr'):
            require(digest(evidence / (command['label'] + '.' + stream)) == command[stream + '_sha256'],
                    'original layout command output bytes differ: ' + command['label'])
    require(set(result['binaries']) == {'driver-layout'}, 'unexpected new binary inventory')
    binary = result['binaries']['driver-layout']
    require(digest(evidence / 'driver-layout') == binary['sha256'] and
            (evidence / 'driver-layout').stat().st_size == binary['bytes'], 'actual controlled driver binary differs')
    build = by_label['layout-build-driver']['argv']
    require(len(build) == 7 and build[:3] == [legacy['toolchain']['cc']['path'], '-O3', '-std=c11'] and
            Path(build[3]).name == 'driver_layout.c' and build[4:6] == ['-ldl', '-o'] and
            Path(build[6]).name == 'driver-layout', 'actual layout driver compiler flags or input differs')
    recorded_directory = Path(build[6]).parent
    require(digest(Path(build[3])) == protocol['controlled_driver']['sha256'], 'actual layout compiler input bytes differ')
    require(by_label['layout-disassembly-driver']['argv'] == ['objdump', '-d', str(recorded_directory / 'driver-layout')],
            'layout disassembly subject differs')
    expected_sums = independent_checksums(protocol)
    samples_checked = 0
    for index, (case, row) in enumerate(zip(controlled, result['rows'][763:])):
        require(all(row[name] == value for name, value in case.items()) and row['phase'] == 'controlled-layout',
                'controlled case identity, order or layout differs')
        library, symbol = v6_reader.expected_binding((case['mode'], case['arm'], case['length']))
        require((row['library'], row['symbol']) == (library, symbol), 'same-build case/library/symbol binding differs')
        require(library in legacy['binaries'], 'controlled case has no original same-build library')
        calls = protocol['span_iterations'][str(case['length'])]
        label = f"layout-case-{index:04d}-{case['mode']}-{case['arm']}-{case['length']}-{case['layout']}"
        require(by_label[label]['argv'] == [str(recorded_directory / 'driver-layout'), case['mode'],
                    str(recorded_directory / 'original-v6' / library), symbol, '21', str(calls),
                    str(case['length']), str(case['gap']), case['address_order']], 'actual controlled driver invocation differs')
        actual = [json.loads(line) for line in (evidence / (label + '.stdout')).read_text().splitlines()]
        require(actual == [row['layout_observation'], *row['samples']], 'retained layout stdout differs from result rows')
        source, destination = validate_observation(row['layout_observation'], case, affinity)
        samples = row['samples']
        require(len(samples) == 21 and [s['batch'] for s in samples] == list(range(21)), 'incomplete controlled batches')
        for sample in samples:
            require(type(sample['calls']) is int and sample['calls'] == calls and
                    type(sample['elapsed_ns']) is int and sample['elapsed_ns'] > 0 and
                    type(sample['checksum']) is int and sample['checksum'] == expected_sums[case['mode'], case['length']] and
                    sample['source_base'] == source and sample['destination_base'] == destination and
                    type(sample['ns_per_call']) in (int, float) and math.isfinite(sample['ns_per_call']) and
                    sample['ns_per_call'] > 0 and abs(sample['ns_per_call'] - sample['elapsed_ns'] / calls) <= 5.1e-10,
                    'controlled checksum, timing division or pointer stability differs')
            samples_checked += 1
        require(row['median_ns_per_call'] == statistics.median(s['ns_per_call'] for s in samples) and
                row['max_ns_per_call'] == max(s['ns_per_call'] for s in samples), 'controlled timing summary differs')
    require(samples_checked == 31878, 'controlled sample inventory incomplete')
    for stage in ('before', 'after'):
        require(by_label['layout-source-commit-' + stage]['argv'] == ['git', 'rev-parse', 'HEAD'] and
                by_label['layout-source-status-' + stage]['argv'] == ['git', 'status', '--porcelain=v1', '--untracked-files=no'],
                'source-state command differs')
        require((evidence / ('layout-source-commit-' + stage + '.stdout')).read_text().strip() == result['source_commit'] and
                not (evidence / ('layout-source-status-' + stage + '.stdout')).read_text().strip(),
                'tracked source changed during layout phase')
        require(by_label['layout-runtime-identity-' + stage]['argv'] ==
                    [str(recorded_directory / 'original-v6/runtime-identity')] and
                (evidence / ('layout-runtime-identity-' + stage + '.stdout')).read_bytes() ==
                    (original / 'runtime-identity-after.stdout').read_bytes(), 'runtime IFUNC differs between phases')
    return {'ok': True, 'scope': 'original files and complete two-phase record readback; no new execution',
            'source_commit': result['source_commit'], 'result_sha256': digest(path), 'cases': 2281, 'samples': 47901,
            'original_v6_readback': checked_v6, 'controlled_cases': 1518, 'controlled_samples': samples_checked,
            'controlled_commands': 1526, 'same_build_libraries_reused': True, 'complete_original_763_rows_preserved': True,
            'total_commands': 2333, 'total_binaries': 34,
            'phase_coverage': 'lower base 0 mod 4096, gaps 131072 and 131136, both copy address orders',
            'all_alignments_or_physical_placements_covered': False,
            'native_components_or_installation_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--protocol-only', action='store_true')
    group.add_argument('--result', type=Path)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--expected-commit')
    parser.add_argument('--solver-library', type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    reader_path = root / 'tools/read_hia_verified_kernel_campaign_v6.py'
    spec = importlib.util.spec_from_file_location('hia_v7_independent_v6_reader', reader_path)
    v6 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v6)
    previous_path = args.previous or root / v6.PREVIOUS_RELATIVE
    previous, raw = v6.read_json(previous_path)
    require(sha256(raw).hexdigest() == v6.PREVIOUS_JSON_SHA256, 'historical complete v5 record changed')
    if previous_path.read_bytes().startswith(b'\x1f\x8b'):
        require(digest(previous_path) == v6.PREVIOUS_GZIP_SHA256, 'historical gzip bytes changed')
    original_protocol, profiles, audit = v6.audit_protocol(root, previous)
    protocol = audit_protocol(root, original_protocol)
    cases = independent_layout_inventory(v6, original_protocol)
    output = {'original_protocol_audit': audit,
              'layout_protocol_audit': {'ok': True, 'cases': 2281, 'samples': 47901,
                                        'controlled_cases': len(cases), 'protocol_sha256': digest(root / PROTOCOL_PATH),
                                        'native_benchmark_observed': False}}
    if args.result is not None:
        output['result_readback'] = readback(root, args.result.resolve(strict=True), v6, previous,
                                           original_protocol, profiles, expected_commit=args.expected_commit,
                                           solver_library=args.solver_library)
    print(json.dumps(output, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'ok': False, 'error': {'type': type(exc).__name__, 'message': str(exc)}}), file=sys.stderr)
        raise SystemExit(1)
