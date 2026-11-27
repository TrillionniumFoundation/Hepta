import hashlib
import json
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

BASE = Path('/workspace/scratch/589c0a6dd85b')
REPO = BASE / 'Hepta'
sys.path.insert(0, str(REPO))
from tools.read_hia_cold_native_transport import decode_original_process_streams

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def verify(raw, expected):
    assert pin(raw) == {k: expected[k] for k in ('bytes', 'sha256')}, (pin(raw), expected)

def git_bytes(commit, path):
    return subprocess.run(['git', 'show', commit + ':' + path], cwd=REPO,
                          check=True, capture_output=True).stdout

report = {'schema': 'hepta.hia.root-component-integration-readback.v1',
          'base_commit': '06d21f6032d7b3a946b1d6581a13c5cfd5fa4375',
          'scope': 'Independent byte, original native response, and evidence readback; no execution or whole-stack qualification is inferred.'}
c13_repo = Path('/tmp/hepta-c13-recovery-589c')
c13 = c13_repo / 'docs/qualification/hia-assembly-wire-recovery-20261127-589c'
receipt = json.loads((c13 / 'receipt.json').read_bytes())
for name, expected in receipt['evidence'].items():
    verify((c13 / name).read_bytes(), expected)
for name, expected in receipt['implementation_files'].items():
    verify((c13_repo / name).read_bytes(), expected)
assert set(receipt['evidence']) | {'receipt.json'} == {
    str(p.relative_to(c13)) for p in c13.rglob('*') if p.is_file()}
rows = []
for label, component in receipt['compile_components'].items():
    directory = c13 / 'native-component'
    request_raw = (directory / (label + '.request.json')).read_bytes()
    record_raw = (directory / (label + '.process-streams.json')).read_bytes()
    stored = {name: (directory / (label + '.process.' + name + '.zlib')).read_bytes()
              for name in ('stdout', 'stderr')}
    record, streams = decode_original_process_streams(record_raw, request_raw, stored, label=label)
    request = json.loads(request_raw)
    observed = json.loads((directory / (label + '.receipt.json')).read_bytes())
    source = git_bytes(component.get('source_commit', '5622dafbcfa10ad0c6f99214994ee7dcf71523e0'), component['source'])
    verify(source, {'bytes': component['source_bytes'], 'sha256': component['source_sha256']})
    raw = streams['stdout']
    assert record['returncode'] == 0 and not record['timed_out'] and streams['stderr'] == b''
    assert raw[:8] == b'HIAOBR02'
    assert len(raw) == 24 + len(source) + request['capacity'] + request['workspace_size']
    assert struct.unpack_from('<2Q', raw, 8) == (observed['result_u64'], observed['native_elapsed_ns'])
    assert raw[24:24+len(source)] == source
    output = raw[24+len(source):24+len(source)+request['capacity']]
    assert hashlib.sha256(output).hexdigest() == observed['output_sha256']
    assert observed['core_u32'] == observed['produced_bytes'] == component['bytes']
    image = output[:component['bytes']]
    verify(image, component)
    assert observed['produced_sha256'] == component['sha256']
    assert request['observer_sha256'] == receipt['observer']['sha256'] == observed['runner_sha256']
    assert request['image_sha256'] == receipt['compiler']['sha256'] == observed['artifact_sha256']
    assert request['source_sha256'] == component['source_sha256']
    rows.append({'component': label, 'source': pin(source), 'produced_image': pin(image),
                 'original_stdout': pin(raw), 'original_process_returncode': 0,
                 'source_echo_exact': True, 'image_echo_exact': True,
                 'native_elapsed_ns': observed['native_elapsed_ns']})
assert receipt['guarded_native_component']['cases'] == 114
assert receipt['guarded_native_component']['mismatches'] == 0
assert receipt['qualification_boundary']['whole_native_qualified'] is False
report['assembly_wire'] = {'receipt': pin((c13/'receipt.json').read_bytes()),
                          'evidence_files_verified': len(receipt['evidence']),
                          'implementation_files_verified': len(receipt['implementation_files']),
                          'original_native_processes': rows,
                          'qualification_boundary': receipt['qualification_boundary']}

perf_repo = BASE/'hepta-audit-current/perf-native-source-v2'
perf_file = perf_repo/'docs/HIA_NATIVE_COLD_PERFORMANCE_COMPONENT_QUALIFICATION.json'
perf = json.loads(perf_file.read_bytes())
archive = perf_repo/perf['evidence']['path']
verify(archive.read_bytes(), perf['evidence'])
with tarfile.open(archive, 'r:gz') as tar:
    files = {m.name: m for m in tar.getmembers() if m.isfile()}
    assert len(files) == len(tar.getmembers()) == len(perf['evidence']['members'])
    assert files.keys() == perf['evidence']['members'].keys()
    for name, expected in perf['evidence']['members'].items():
        verify(tar.extractfile(files[name]).read(), expected)
for name, expected in perf['sources'].items():
    verify((perf_repo/name).read_bytes(), expected['current'])
    if expected['original'] is not None:
        original = git_bytes(perf['baseline_source_commit'], name)
        verify(original, expected['original'])
        assert original == (REPO/name).read_bytes(), name
    else:
        assert not (REPO/name).exists(), name
assert perf['whole_cold_qualified'] is False and perf['whole_native_delivery_qualified'] is False
assert perf['unchanged_full_cold_contract']['native_deadline_seconds'] == 180
assert perf['unchanged_full_cold_contract']['phases'] == 60
assert perf['unchanged_full_cold_contract']['nodes'] == 479882
report['cold_performance'] = {'receipt': pin(perf_file.read_bytes()), 'archive': pin(archive.read_bytes()),
                            'archive_members_verified': len(perf['evidence']['members']),
                            'source_files_verified': len(perf['sources']),
                            'full_cold_qualification': False, 'retained_full_cold_failures': perf['retained_full_cold_failures']}
out = BASE/'consolidation-evidence/component-integration-root-readback.json'
out.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
print(json.dumps({'report': str(out), **pin(out.read_bytes()),
                  'c13_evidence': len(receipt['evidence']), 'c13_native_streams': len(rows),
                  'perf_archive_members': len(perf['evidence']['members']),
                  'perf_sources': len(perf['sources'])}))
