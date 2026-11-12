"""Freeze the original closed r4b1 run and its independent read-only audit."""
from pathlib import Path
from hashlib import sha1, sha256
import importlib.util
import json
import os

BASE = Path('/workspace/scratch/e26ed3e2edcf')
ROOT = BASE / 'native-cli-json-graph-r1'
HERE = ROOT / 'source-authoring-r4b1-receiver-r1'
PREFIX = 'experiments/hia_cli_json_graph_20261112/source-authoring-r4b1-actual-r1'
PARENT = '1cacd301013725b42380da34963ba4d9283fe927'
PARENT_TREE = '5bd0af76404d00148e7356690787aed7ab4c0da0'


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
    reader = HERE / 'audit_source_only.py'
    if sha256(reader.read_bytes()).hexdigest() != '7a7e224fe403bc6abd1c42213999d865e93d8c802dae94ff834d8ddd1795a4ff':
        raise ValueError('fixed read-only receiver differs')
    spec = importlib.util.spec_from_file_location('closed_original_reader', reader)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    paths = {}
    request_root = ROOT / 'source-authoring-r4b1'
    for directory in ('actual', 'guardian'):
        members = helper.namespace(request_root / directory)
        for name in sorted(members):
            paths['originals/' + directory + '/' + name] = request_root / directory / name
    if len(paths) != 17:
        raise ValueError('seventeen original request, guardian and output files required')
    launch_root = BASE / 'root/cli-r4b1-source-actual-r1'
    if set(helper.namespace(launch_root)) != set(helper.ROOT_PINS):
        raise ValueError('five original launch files differ')
    for name in sorted(helper.ROOT_PINS):
        paths['root-launch/' + name] = launch_root / name
    paths['root-launch/review_run_cli_r4b1_source.py'] = BASE / 'root/review_run_cli_r4b1_source.py'
    for name in ('audit_source_only.py', 'PREEXEC.json', 'READER-GIT-ACK.json',
                 'actual-readonly-r1/AUDIT.json', 'actual-readonly-r1/EXECUTION-SDK.json',
                 'assemble_evidence.py'):
        paths['receiver/' + name] = HERE / name
    records = {name: dict(local_path=str(path), **pin(helper.original(path)[0]))
               for name, path in sorted(paths.items())}
    report = helper.strict_json(helper.original(request_root / 'actual/REPORT.json')[0])
    guard = helper.strict_json(helper.original(request_root / 'guardian/guardian.json')[0])
    audit = helper.strict_json(helper.original(HERE / 'actual-readonly-r1/AUDIT.json')[0])
    if (report['status'] != 'TWO_NEW_SOURCE_COMPONENTS_PASS_PENDING_OUTER_GUARDIAN'
            or guard['status'] != 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            or audit['status'] != 'READONLY_TWO_NEW_SOURCE_COMPONENTS_PASS'
            or len(audit['checks']) != 777 or audit['errors']):
        raise ValueError('actual original or independent audit status differs')
    for path, actual in audit['originals'].items():
        _, current = helper.original(Path(path), helper.PYTHON_BYTES if path == helper.PYTHON else 16 << 20)
        if current != actual:
            raise ValueError('already-audited original changed: ' + path)
    for mapping in (audit['actual_namespace'], audit['root_launch_namespace']):
        for actual in mapping.values():
            if helper.original(Path(actual['path']))[1] != actual:
                raise ValueError('original output changed before evidence freeze')
    handoff = {
        'schema': 'hia.cli-json.r4b1.source-actual.handoff.v1',
        'status': 'TWO_NEW_SOURCE_COMPONENTS_PASS',
        'source_request_commit': PARENT,
        'source_request_tree': PARENT_TREE,
        'source_request_prefix': 'experiments/hia_cli_json_graph_20261112/source-authoring-r4b1/',
        'previous_failed_source_operation_commit': '60e30e1bd5ad5a7434ea0019767e5c9210e32be7',
        'scope': 'One actual two-component source invocation, original public Core document roundtrips and nine structural caps, plus an independent read-only audit. No execution replay.',
        'original_files': {'worker_outputs': 13, 'guardian_and_request': 4, 'root_launch': 5},
        'inputs': {'fixed': 174, 'source_files': 167, 'source_bytes': 2632579,
                   'all_original_bytes_and_identities_unchanged': True},
        'components': [{'name': row['name'], 'module': row['module'],
                        'status': row['status'], 'elapsed_ns': row['elapsed_ns'],
                        'assembly': row['assembly']} for row in report['components']],
        'component_metrics': audit['component_metrics'],
        'original_worker_status': report['status'],
        'original_guardian_status': guard['status'],
        'original_worker_elapsed_ns': audit['worker_elapsed_ns'],
        'original_owner_event_elapsed_ns': audit['owner_event_elapsed_ns'],
        'original_owner_seconds': 180,
        'original_cleanup_seconds': 3,
        'original_natural_exit': {'returncode': 0, 'events': 4, 'echild': True,
                                  'leader_reaped': True, 'kill_or_overflow': False},
        'independent_readonly_audit': {'status': audit['status'], 'checks': len(audit['checks']),
                                     'errors': [], 'path': 'receiver/actual-readonly-r1/AUDIT.json'},
        'root_launcher_return_record_existed': True,
        'root_launcher_returncode': 0,
        'root_launch_record_reconstructed': False,
        'limits_exclusions': [
            'The nine frozen structural caps were observed independently for both components.',
            'The compiler line-count gate was not executed; source line counts are diagnostic only.',
            'Private C ABI, owned CALL, actual generator frames and object input semantics were not executed.',
            'The previously successful four source components were dependencies only and were not regenerated.',
            'The old r4b scalar Div failure and its launch-reporting error remain unchanged in their own evidence commit.',
        ],
        'original_cli_17_executed': 0,
        'trace_46_executed': 0,
        'native_or_installation_or_cold_or_full_executed': False,
        'old_request_or_unknown_operation_replayed': False,
        'previous_failure_reclassified': False,
        'files': records,
    }
    create(HERE / 'HANDOFF.json', wire(handoff))
    paths['HANDOFF.json'] = HERE / 'HANDOFF.json'
    packet = {'parent_commit': PARENT, 'parent_tree': PARENT_TREE,
              'prefix': PREFIX, 'files': [{'path': PREFIX + '/' + name,
                                         'local_path': str(path), **pin(helper.original(path)[0])}
                                        for name, path in sorted(paths.items())]}
    create(HERE / 'PUBLICATION-PACKET.json', wire(packet))
    print(json.dumps({'files': len(paths), 'bytes': sum(row['bytes'] for row in packet['files']),
                      'handoff': pin((HERE / 'HANDOFF.json').read_bytes()),
                      'packet': str(HERE / 'PUBLICATION-PACKET.json')}, sort_keys=True))


if __name__ == '__main__':
    main()
