"""Bounded synthetic resource/archive controls; never run a model or native binary."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile

ROOT = Path('/workspace/scratch/5567a9db5cf4/hepta-work')
HERE = ROOT / 'experiments/hia_agent_assembly_recovery_20261030'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sources = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
           for name in ('resource_gate.py', 'run_recovery.py')}
gate = load('recovery_resource_review', HERE / 'resource_gate.py')
runner = load('recovery_runtime_review', HERE / 'run_recovery.py')
records = []
files = {'/sys/fs/cgroup/cgroup.controllers': ''}


def read_text(path):
    if path not in files:
        raise FileNotFoundError(path)
    return files[path]


for label, membership, expected in (
    ('unified_unbounded_root', '0::/\n', True),
    ('hybrid_v1_cpu_memory_must_refuse', '5:cpu,cpuacct:/limited\n4:memory:/limited\n0::/\n', False),
):
    result = gate.evaluate(affinity=set(range(8)), cpu_count=8,
        meminfo='MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\n', membership=membership,
        mountinfo='29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n', read_text=read_text)
    records.append({'case': label, 'expected_eligible': expected, 'actual': result,
                    'passed': result['eligible'] is expected})


def regular(name, data=b'synthetic non-executable fixture\n'):
    item = tarfile.TarInfo(name)
    item.size = len(data)
    return item, data


def symlink(name, target):
    item = tarfile.TarInfo(name)
    item.type, item.linkname = tarfile.SYMTYPE, target
    return item, None


with tempfile.TemporaryDirectory(prefix='hepta-recovery-review-') as temporary:
    root = Path(temporary)
    special = tarfile.TarInfo('device')
    special.type, special.devmajor, special.devminor = tarfile.CHRTYPE, 1, 3
    cases = [
        ('regular_and_internal_symlink', [regular('bin/llama-server'), regular('bin/libx.so.1'),
                                         symlink('bin/libx.so', 'libx.so.1')], True),
        ('parent_path_refused', [regular('../outside')], False),
        ('absolute_path_refused', [regular(str(root / 'outside'))], False),
        ('escaping_symlink_refused', [regular('bin/llama-server'), symlink('bin/libx.so', '../../outside')], False),
        ('duplicate_normalized_path_refused', [regular('bin/llama-server'), regular('bin/./llama-server')], False),
        ('special_device_refused', [(special, None)], False),
        ('member_limit_refused', [regular('item-' + str(i), b'') for i in range(513)], False),
    ]
    for index, (label, members, expected) in enumerate(cases):
        archive = root / (str(index) + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as stream:
            for member, body in members:
                stream.addfile(member, io.BytesIO(body) if body is not None else None)
        evidence = root / ('evidence-' + str(index)); evidence.mkdir()
        success, failure = False, None
        try:
            runner.extract_runtime(archive, root / ('extract-' + str(index)), evidence)
            success = True
        except Exception as error:
            failure = {'type': type(error).__name__, 'message': str(error)}
        retained = json.loads((evidence / 'RUNTIME_EXTRACTION.json').read_text())
        records.append({'case': label, 'expected_accepted': expected, 'accepted': success,
                        'failure': failure, 'retained_passed': retained['passed'],
                        'failure_or_success_cost_retained': type(retained['extraction_and_identity_wall_ns']) is int,
                        'passed': success is expected and retained['passed'] is success})

unchanged = all(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest
                for name, digest in sources.items())
report = {'schema': 'hepta.agent.recovery.bounded-io-review.v1', 'sources': sources,
          'sources_unchanged_during_review': unchanged, 'records': records,
          'passed': unchanged and all(row['passed'] for row in records),
          'scope': {'synthetic_small_archives_only': True, 'actual_downloads': 0,
                    'model_calls': 0, 'native_program_runs': 0, 'performance_measurement': False,
                    'member_limit_refusal_does_not_prove_early_iteration_bound': True}}
out = Path('/tmp/hepta-recovery-io-review-01.json')
with out.open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps({'passed': report['passed'], 'controls': len(records), 'report': str(out),
                  'source_unchanged': unchanged,
                  'failures': [row['case'] for row in records if not row['passed']]}))
