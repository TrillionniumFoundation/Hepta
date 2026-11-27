"""Bounded native emitter observation; does not qualify complete cold time."""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import json
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.hia_native_seed_test_support import NativeSeeds

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--bootstrap', type=Path, required=True)
parser.add_argument('--qualification', type=Path, required=True)
parser.add_argument('--baseline-commit', required=True)
args = parser.parse_args()
OUTPUT = args.output.resolve()
seeds = NativeSeeds(ROOT, args.bootstrap, OUTPUT)
report = {'schema': 'hepta.hia.compact-immediate-emitter-observation.v1',
          'passed': False, 'whole_cold_qualified': False,
          'baseline_commit': args.baseline_commit,
          'scope': 'Same-input alternating native emitter timings, excluding projection and process launch.',
          'profiles': {}, 'workloads': {}}

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def image(raw):
    return NativeHiaJsonImage(raw, sha256(raw).hexdigest())

def project(raw):
    core = seeds.invoke(OUTPUT / 'hia-seed-assembly', raw, '--agent-compact')
    return seeds.invoke(OUTPUT / 'hia-seed-projector', b'[' + core + b',"f0",1]')

GUARD = b'\x91\x26\xd4\x68' * 4
CAPACITY = 1 << 20

def invoke(native, wire):
    source = ctypes.create_string_buffer(GUARD + wire + GUARD, len(wire) + 32)
    output = ctypes.create_string_buffer(GUARD + b'\xa5' * CAPACITY + GUARD, CAPACITY + 32)
    workspace = ctypes.create_string_buffer(GUARD + b'\x6d' * CAPACITY + GUARD, CAPACITY + 32)
    started = time.perf_counter_ns()
    count = native._entry(ctypes.byref(source, 16), len(wire),
                          ctypes.byref(output, 16), CAPACITY,
                          ctypes.byref(workspace, 16), CAPACITY)
    elapsed = time.perf_counter_ns() - started
    assert 0 < count <= CAPACITY, count
    assert source.raw == GUARD + wire + GUARD
    assert output.raw[:16] == output.raw[-16:] == GUARD
    assert workspace.raw[:16] == workspace.raw[-16:] == GUARD
    assert output.raw[16 + count:-16] == b'\xa5' * (CAPACITY - count)
    return output.raw[16:16 + count], elapsed

try:
    assert len(args.baseline_commit) == 40 and all(c in '0123456789abcdef' for c in args.baseline_commit)
    def baseline_source(name):
        return subprocess.check_output(['/usr/bin/git', 'show', args.baseline_commit +
            ':examples/hia_bootstrap/' + name + '.hepta'], cwd=ROOT, timeout=30)
    script = Path(__file__).read_bytes()
    report['observer_source'] = pin(script)
    qualification_raw = (args.qualification / 'qualification.json').read_bytes()
    report['qualification'] = pin(qualification_raw)
    qualification = json.loads(qualification_raw)
    assert qualification['passed'] and qualification['source_unchanged']
    for name, expected in qualification['source_pins'].items():
        assert pin((ROOT / name).read_bytes()) == expected
    emitters = {}
    for profile in ('bulk', 'endian'):
        source = baseline_source('seed_cold_' + profile + '_backend')
        wire = project(source)
        first = seeds.compile(source, 'v1')
        first_image = image(first)
        second, _ = invoke(first_image, wire)
        baseline = image(second)
        third, _ = invoke(baseline, wire)
        assert second == third
        candidate_raw = (args.qualification / (profile + '-B2.flat')).read_bytes()
        assert pin(candidate_raw) == qualification['profiles'][profile]['B2']
        candidate = image(candidate_raw)
        emitters[profile] = (baseline, candidate)
        report['profiles'][profile] = {'baseline_source': pin(source),
            'baseline_B1': pin(first), 'baseline_B2': pin(second),
            'baseline_B3': pin(third), 'candidate_B2': pin(candidate_raw)}
        first_image._mapping.close()
    for name, profile in [('cold_qualification_driver', 'bulk'),
                          ('cold_sha256_nonalias', 'endian'),
                          ('cold_source_bootstrap_entry', 'bulk')]:
        source = (ROOT / 'examples/hia_bootstrap' / (name + '.hepta')).read_bytes()
        assert source == baseline_source(name), ('changed observation workload', name)
        wire = project(source)
        row = {'source': pin(source), 'wire': pin(wire), 'profile': profile,
               'baseline_ns': [], 'candidate_ns': []}
        outputs = {}
        for trial in range(10):
            order = (0, 1) if trial % 2 == 0 else (1, 0)
            for which in order:
                label = ('baseline', 'candidate')[which]
                flat, elapsed = invoke(emitters[profile][which], wire)
                if label in outputs:
                    assert flat == outputs[label]
                outputs[label] = flat
                row[label + '_ns'].append(elapsed)
        for label, raw in outputs.items():
            (OUTPUT / (name + '-' + label + '.flat')).write_bytes(raw)
            row[label + '_image'] = pin(raw)
            row[label + '_median_ns'] = statistics.median(row[label + '_ns'])
        row['candidate_over_baseline_median'] = row['candidate_median_ns'] / row['baseline_median_ns']
        report['workloads'][name] = row
        print('NATIVE_EMITTER_OBSERVATION', name, row['baseline_image']['bytes'],
              row['candidate_image']['bytes'], row['candidate_over_baseline_median'], flush=True)
    assert Path(__file__).read_bytes() == script
    for name, expected in qualification['source_pins'].items():
        assert pin((ROOT / name).read_bytes()) == expected
    report['source_unchanged'] = True
    report['passed'] = True
finally:
    seeds.save()
    (OUTPUT / 'observation.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')

