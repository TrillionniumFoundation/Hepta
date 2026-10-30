"""Independent bounded fake-kernel admission controls; no real resource probes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

source = Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/resource_gate.py')
before = source.read_bytes()
spec = importlib.util.spec_from_file_location('recovery_resource_review_02', source)
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
GB = 1024 ** 3
base = {
    'affinity': list(range(8)), 'cpu_count': 8,
    'meminfo': 'MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\n',
    'membership': '0::/parent/child\n',
    'mountinfo': '29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
    'files': {
        '/sys/fs/cgroup/cgroup.controllers': 'cpu memory',
        '/sys/fs/cgroup/cgroup.subtree_control': 'cpu memory',
        '/sys/fs/cgroup/parent/cgroup.controllers': 'cpu memory',
        '/sys/fs/cgroup/parent/cgroup.subtree_control': 'cpu memory',
        '/sys/fs/cgroup/parent/cpu.max': '400000 100000',
        '/sys/fs/cgroup/parent/memory.max': str(8 * GB),
        '/sys/fs/cgroup/parent/memory.current': str(4 * GB),
        '/sys/fs/cgroup/parent/child/cgroup.controllers': 'cpu memory',
        '/sys/fs/cgroup/parent/child/cpu.max': 'max 100000',
        '/sys/fs/cgroup/parent/child/memory.max': 'max',
        '/sys/fs/cgroup/parent/child/memory.current': str(GB),
    },
}
cases = []


def add(name, expected, changes=None, file_changes=None):
    value = copy.deepcopy(base)
    value.update(changes or {})
    for key, item in (file_changes or {}).items():
        if item is None:
            value['files'].pop(key, None)
        else:
            value['files'][key] = item
    cases.append((name, expected, value))


add('exact_4_cpu_4GiB_parent_threshold', True)
add('fractional_3_5_cpu_parent_refused', False, file_changes={'/sys/fs/cgroup/parent/cpu.max': '350000 100000'})
add('child_quota_below_parent_refused', False, file_changes={'/sys/fs/cgroup/parent/child/cpu.max': '300000 100000'})
add('affinity_three_refused', False, {'affinity': [0, 1, 2]})
add('cpu_count_three_refused', False, {'cpu_count': 3})
add('parent_headroom_3GiB_refused', False, file_changes={'/sys/fs/cgroup/parent/memory.current': str(5 * GB)})
add('child_headroom_3GiB_refused', False, file_changes={'/sys/fs/cgroup/parent/child/memory.max': str(4 * GB)})
add('negative_headroom_refused', False, file_changes={'/sys/fs/cgroup/parent/memory.current': str(9 * GB)})
add('host_available_3GiB_refused', False, {'meminfo': 'MemAvailable: 3145728 kB\n'})
add('host_memory_unknown_refused', False, {'meminfo': 'MemTotal: 16777216 kB\n'})
add('duplicate_available_refused', False, {'meminfo': 'MemAvailable: 8388608 kB\nMemAvailable: 8388608 kB\n'})
add('hybrid_membership_refused', False, {'membership': '5:cpu,cpuacct:/v1\n4:memory:/v1\n0::/parent/child\n'})
add('missing_enabled_child_cpu_interface_refused', False, file_changes={'/sys/fs/cgroup/parent/child/cpu.max': None})
add('inactive_child_interfaces_with_bound_parent', True, file_changes={
    '/sys/fs/cgroup/parent/cgroup.subtree_control': '',
    '/sys/fs/cgroup/parent/child/cgroup.controllers': '',
    '/sys/fs/cgroup/parent/child/cpu.max': None,
    '/sys/fs/cgroup/parent/child/memory.max': None,
    '/sys/fs/cgroup/parent/child/memory.current': None,
})
add('malformed_zero_period_refused', False, file_changes={'/sys/fs/cgroup/parent/cpu.max': 'max 0'})
add('malformed_memory_current_refused', False, file_changes={'/sys/fs/cgroup/parent/memory.current': 'unknown'})
add('ambiguous_visible_mount_refused', False, {'mountinfo': base['mountinfo'] + '30 23 0:26 / /other/cgroup rw - cgroup2 cgroup rw\n'})
add('unsupported_architecture_refused', False, {'machine': 'aarch64'})

rows = []
for name, expected, value in cases:
    files = value['files']
    def read_text(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]
    args = {key: item for key, item in value.items() if key != 'files'}
    actual = gate.evaluate(read_text=read_text, **args)
    rows.append({'case': name, 'expected_eligible': expected, 'input': value, 'actual': actual,
                 'passed': actual['eligible'] is expected})
unchanged = source.read_bytes() == before
record = {'schema': 'hepta.agent.recovery.resource-review.v2',
          'source_sha256': hashlib.sha256(before).hexdigest(), 'source_unchanged': unchanged,
          'passed': unchanged and all(row['passed'] for row in rows), 'rows': rows,
          'scope': 'pure fake kernel metadata; 0 network/model/native runs; visible-hierarchy observation only'}
output = Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/independent-runtime-review01/final-source-controls02/resource.json')
with output.open('x') as stream:
    json.dump(record, stream, indent=2, sort_keys=True); stream.write('\n')
print(json.dumps({'passed': record['passed'], 'controls': len(rows), 'source_sha256': record['source_sha256'],
                  'source_unchanged': unchanged, 'failed': [r['case'] for r in rows if not r['passed']], 'report': str(output)}))
