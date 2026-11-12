"""Package already-closed r4b originals without executing any product."""
from pathlib import Path
from hashlib import sha1, sha256
import json
import os

BASE = Path('/workspace/scratch/e26ed3e2edcf')
ROOT = BASE / 'native-cli-json-graph-r1'
HERE = ROOT / 'source-authoring-r4b-receiver-r1'
PREFIX = 'experiments/hia_cli_json_graph_20261112/source-authoring-r4b-actual-r1'
PARENT = '6ae4d8765678fe1e8c54c365c595d1528655ea62'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError('evidence creation readback differs')


def main():
    paths = {}
    request_root = ROOT / 'source-authoring-r4b'
    for directory in ('actual', 'guardian'):
        for path in sorted((request_root / directory).iterdir()):
            if not path.is_file() or path.is_symlink():
                raise ValueError('unexpected original member')
            paths['originals/' + directory + '/' + path.name] = path
    if len(paths) != 15:
        raise ValueError('actual original denominator differs')
    reconciliation_root = BASE / 'root/cli-r4b-source-actual-r1'
    for path in sorted(reconciliation_root.iterdir()):
        if not path.is_file() or path.is_symlink():
            raise ValueError('unexpected root reconciliation member')
        paths['root-reconciliation/' + path.name] = path
    paths['root-reconciliation/review_run_cli_r4b_source.py'] = BASE / 'root/review_run_cli_r4b_source.py'
    for name in ('audit_source_only.py', 'history/audit_source_only.r1.py',
                 'actual-readonly-r1/AUDIT.json', 'actual-readonly-r2/AUDIT.json',
                 'actual-readonly-r2/EXECUTION-SDK.json', 'assemble_evidence.py'):
        paths['receiver/' + name] = HERE / name
    records = {name: dict(local_path=str(path), **pin(path.read_bytes()))
               for name, path in sorted(paths.items())}
    report = json.loads((request_root / 'actual/REPORT.json').read_bytes())
    audit = json.loads((HERE / 'actual-readonly-r2/AUDIT.json').read_bytes())
    if report['status'] != 'HOLD' or audit['status'] != 'CLOSED_SOURCE_FAILURE_ORIGINALS_VERIFIED':
        raise ValueError('original status or read-only result differs')
    if len(audit['checks']) != 378 or audit['errors']:
        raise ValueError('read-only audit denominator differs')
    handoff = {
        'schema': 'hia.cli-json.r4b.source-failure.handoff.v1',
        'status': 'ORIGINAL_SOURCE_ONLY_HOLD_PRESERVED',
        'original_source_request_commit': PARENT,
        'original_source_request_tree': 'af06d6ce05a4973eda544e728c342e7f1fae38e8',
        'original_request_prefix': 'experiments/hia_cli_json_graph_20261112/source-authoring-r4b/',
        'root_reconciliation_commit': 'de63d40dfac4d969ed0254b83cfbc8d0ce2f5a88',
        'scope': 'Already-closed original source-only run and independent read-only receipt audit; no execution replay.',
        'original_components': [{'name': row['name'], 'status': row['status'], 'error': row.get('error')}
                                for row in report['components']],
        'original_worker_status': report['status'],
        'original_guardian_status': audit['observed_guardian_status'],
        'original_worker_elapsed_ns': audit['worker_elapsed_ns'],
        'original_owner_event_elapsed_ns': audit['owner_event_elapsed_ns'],
        'original_owner_seconds': 180,
        'original_cleanup_seconds': 3,
        'original_inputs': 174,
        'original_source_files': 167,
        'original_source_bytes': 2631235,
        'original_input_bytes_unchanged': True,
        'original_natural_exit': {'returncode': 1, 'events': 4, 'echild': True,
                                  'leader_reaped': True, 'kill_or_overflow': False},
        'component_metrics': audit['component_metrics'],
        'independent_readonly_audit': {'status': audit['status'], 'checks': len(audit['checks']),
                                     'errors': [], 'path': 'receiver/actual-readonly-r2/AUDIT.json'},
        'reader_history': [{'revision': 'r1', 'status': 'HOLD',
                            'reason': 'The receiver used a 16 MiB read ceiling for the already-pinned 30,894,944-byte Python executable. No source or original run changed.'},
                           {'revision': 'r2', 'status': audit['status'],
                            'change': 'Bind the exact original Python path and size for that one input; child originals keep the original 16 MiB evidence read ceiling.'}],
        'launcher_reporting_bug': audit['launcher_reporting_bug'],
        'launcher_original_return_record_missing': True,
        'launcher_return_record_reconstructed': False,
        'limits_exclusions': ['Only the nine frozen structural caps were observed for the successful component.',
                              'The compiler line gate was not executed.',
                              'Private C ABI, generator-frame behavior, and object input semantics were not executed.'],
        'previous_four_component_request_replayed': False,
        'original_cli_17_executed': 0,
        'trace_46_executed': 0,
        'native_or_installation_or_cold_or_full_executed': False,
        'original_status_reclassified': False,
        'files': records,
    }
    create(HERE / 'HANDOFF.json', wire(handoff))
    paths['HANDOFF.json'] = HERE / 'HANDOFF.json'
    packet = {'parent_commit': PARENT, 'parent_tree': 'af06d6ce05a4973eda544e728c342e7f1fae38e8',
              'prefix': PREFIX, 'files': [{'path': PREFIX + '/' + name,
                                         'local_path': str(path), **pin(path.read_bytes())}
                                        for name, path in sorted(paths.items())]}
    create(HERE / 'PUBLICATION-PACKET.json', wire(packet))
    print(json.dumps({'files': len(paths), 'bytes': sum(row['bytes'] for row in packet['files']),
                      'handoff': pin((HERE / 'HANDOFF.json').read_bytes()),
                      'packet': str(HERE / 'PUBLICATION-PACKET.json')}, sort_keys=True))


if __name__ == '__main__':
    main()
