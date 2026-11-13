from pathlib import Path
import hashlib
import importlib.util
import json
import os
import statistics
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
BASE = ROOT.parent / 'source-original'
OUT = ROOT / 'comparison-r1'
OUT.mkdir()
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))
from tools import hia_selfhost_contract as candidate
spec = importlib.util.spec_from_file_location('_original_source_guard', BASE / 'tools/hia_selfhost_contract.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
assert reference._source_protocol_current(BASE) is True
assert candidate._source_protocol_current(BASE) is True
assert reference.SOURCE_FILES == candidate.SOURCE_FILES
baseline = reference.file_digests(BASE)
raw_map = (json.dumps(baseline, sort_keys=True, separators=(',', ':')) + '\n').encode()
(OUT / 'FULL-FRESH-MAP.json').write_bytes(raw_map)
watched = [BASE / 'tools/hia_selfhost_contract.py', SOURCE / 'tools/hia_selfhost_contract.py',
           SOURCE / 'docs/HIA_SELFHOST_CORE_SUPPORT.json']
before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in watched}
affinity = sorted(os.sched_getaffinity(0))
rows = []
started = time.time_ns()
error = None
try:
    os.sched_setaffinity(0, {affinity[0]})
    for module in (reference, candidate):
        for unused in range(20000):
            assert module._source_protocol_current(BASE) is True
        for unused in range(2):
            assert module.file_digests(BASE) == baseline
    for kind in ('guard', 'full-fresh-map'):
        for sequence, label in enumerate('ABBAABBA'):
            module = reference if label == 'A' else candidate
            iterations = 20000 if kind == 'guard' else 1
            wall = time.perf_counter_ns()
            cpu = time.process_time_ns()
            if kind == 'guard':
                for unused in range(iterations):
                    if module._source_protocol_current(BASE) is not True:
                        raise AssertionError('standard provider changed')
            else:
                result = module.file_digests(BASE)
            cpu_elapsed = time.process_time_ns() - cpu
            elapsed = time.perf_counter_ns() - wall
            if kind == 'full-fresh-map':
                assert result == baseline
                assert list(result) == list(baseline)
            row = {'kind': kind, 'sequence': sequence, 'variant': label, 'iterations': iterations,
                   'wall_ns': elapsed, 'process_cpu_ns': cpu_elapsed, 'observation_equal': True}
            rows.append(row)
            with (OUT / 'MEASUREMENTS.jsonl').open('a') as stream:
                stream.write(json.dumps(row, sort_keys=True) + '\n')
                stream.flush()
except BaseException:
    error = traceback.format_exc()
    (OUT / 'FAILURE.txt').write_text(error)
finally:
    os.sched_setaffinity(0, affinity)
    after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in watched}
    means = {}
    for kind in ('guard', 'full-fresh-map'):
        means[kind] = {}
        for label in 'AB':
            selected = [r['wall_ns'] / r['iterations'] for r in rows if r['kind'] == kind and r['variant'] == label]
            means[kind][label] = statistics.mean(selected) if selected else None
        if all(means[kind][label] is not None for label in 'AB'):
            means[kind]['observed_reduction_fraction'] = 1 - means[kind]['B'] / means[kind]['A']
    report = {'schema': 'hepta.source-guard-fixed-cpu-abba.v1', 'python': sys.version,
        'status': 'OBSERVATIONS_COMPLETE' if error is None and before == after else 'FAIL',
        'started_utc_ns': started, 'finished_utc_ns': time.time_ns(), 'cpu': affinity[0],
        'affinity_restored': sorted(os.sched_getaffinity(0)) == affinity,
        'maps_equal': all(r['observation_equal'] for r in rows), 'source_unchanged': before == after,
        'map_paths': len(baseline), 'map_sha256': hashlib.sha256(raw_map).hexdigest(),
        'warmup': {'per_variant_guard_calls': 20000, 'per_variant_fresh_maps': 2}, 'rows': rows, 'means_ns': means, 'source_before': before, 'source_after': after,
        'whole_native': False, 'qualification': False, 'original_business_tests_run': 0,
        'limits': ['Actual runtime is recorded; this is a scan diagnostic only.', 'No 3s/5s deadline qualification or causal business improvement claim.',
                   'Every file is freshly read and hashed by both variants in unchanged order.']}
    (OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('rows', 'source_before', 'source_after')}, sort_keys=True))
if error:
    print(error, file=sys.stderr)
    raise SystemExit(1)
