"""Independent data-only readback for the exact Service artifact worker terminal successor.

No producer admission or product module is imported. Raw source and terminal
tags are checked again, including reverse/forward source custody, typed fields,
diagnostic markers, process-specific actual object observations, and old scope.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.hia_slot_operations_qualification_support import canonical, regular_bytes, unique_pairs

AUTHORITY = 'tests/fixtures/service_artifact_worker_terminal_v2.json'
AUTHORITY_SHA256 = '9808c296e7be3a57546b02191aadf8339a87ad696c758527e7e62496ffebdbf4'
WORKERS = {
    1: {'bytes': 8496, 'sha256': '4e6a64b551e34805106fa1d4b888a48f9a2a138d2f82d4091b4412bf65862066'},
    2: {'bytes': 11444, 'sha256': '6352879dc0e58515a6af9b2a586a5efa27f4018fb19d49a379ab72425eebf45a'},
    3: {'bytes': 16086, 'sha256': 'd5f9f7ab7057e19c38aa263ae2acfa3494fec950f6f85299110f7522224dd172'},
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    require(type(raw) is bytes, 'terminal source must be exact bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def equal(left, right):
    require(canonical(left) == canonical(right), 'terminal typed value differs')


def original_source(current, specification):
    equal(digest(current), specification['current'])
    parts = []
    cursor = 0
    previous_original = 0
    movement = 0
    for row in specification['splices']:
        require(set(row) == {'offset', 'before', 'after'}
                and type(row['offset']) is int and row['offset'] >= previous_original
                and type(row['before']) is str and type(row['after']) is str,
                'terminal source splice shape/order differs')
        before, after = row['before'].encode(), row['after'].encode()
        require(before != after, 'terminal source splice is not a change')
        at = row['offset'] + movement
        require(at >= cursor and current[at:at + len(after)] == after,
                'terminal source splice does not match current bytes')
        parts.extend((current[cursor:at], before))
        cursor = at + len(after)
        previous_original = row['offset'] + len(before)
        movement += len(after) - len(before)
    parts.append(current[cursor:])
    original = b''.join(parts)
    equal(digest(original), specification['original'])
    parts, cursor = [], 0
    for row in specification['splices']:
        offset, before, after = row['offset'], row['before'].encode(), row['after'].encode()
        require(original[offset:offset + len(before)] == before,
                'terminal source forward splice does not match original')
        parts.extend((original[cursor:offset], after))
        cursor = offset + len(before)
    require(b''.join((*parts, original[cursor:])) == current,
            'complete terminal successor source did not replay')
    return original


def admit_source_authority(captured, root):
    root = Path(root)
    observation_sources = {}
    for name in ('tests/hia_service_artifact_worker_terminal.py',
                 'tools/read_hia_service_artifact_worker_terminal.py'):
        observation_sources[name] = digest(captured.raw(root / name))
    require(regular_bytes(__file__) == captured.raw(root / 'tools/read_hia_service_artifact_worker_terminal.py'),
            'loaded independent artifact terminal reader differs from captured root')
    raw = captured.raw(root / AUTHORITY)
    require(sha256(raw).hexdigest() == AUTHORITY_SHA256, 'fixed terminal authority digest differs')
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(value['schema'] == 'hepta.service_artifact.worker-terminal-successor.v2'
            and type(value['legacy_lost_ack_exit']) is int and value['legacy_lost_ack_exit'] == 1
            and type(value['current_lost_ack_exit']) is int and value['current_lost_ack_exit'] == 2,
            'explicit terminal version contract differs')
    originals, current = {}, {}
    for name, specification in value['source_successors'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts, 'unsafe terminal source path')
        data = captured.raw(root / name)
        originals[name] = digest(original_source(data, specification))
        current[name] = digest(data)
    equal(digest(captured.raw(root / 'tests/fixtures/worker_unknown_original_r17b/hia_agent_worker.py.txt')),
          WORKERS[1])
    worker = digest(captured.raw(root / 'hepta/hia_agent_worker.py'))
    versions = [version for version, fixed in WORKERS.items() if worker == fixed]
    require(len(versions) == 1, 'undeclared complete worker terminal source')
    version, = versions
    profile = {'version': version, 'lost_ack_exit': 1 if version == 1 else 2, 'worker': worker}
    for name, expected in value['current_dependencies'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts, 'unsafe terminal dependency path')
        equal(digest(captured.raw(root / name)), expected)
    return {'schema': value['schema'], 'authority': digest(raw), 'worker_profile': profile,
            'original_sources': originals, 'current_sources': current,
            'observation_sources': observation_sources,
            'legacy_pass_transferred': False, 'original_Native8_replaced': False}


def verify_terminal(value, stderr, label, profile):
    require(label in ('first', 'replay', 'lost-put-ACK', 'unknown-replay'), 'undeclared terminal case')
    require(type(profile) is dict and set(profile) == {'version', 'lost_ack_exit', 'worker'}
            and type(profile['version']) is int and profile['version'] in WORKERS,
            'undeclared complete worker profile')
    equal(profile, {'version': profile['version'], 'lost_ack_exit': 1 if profile['version'] == 1 else 2,
                    'worker': WORKERS[profile['version']]})
    equal(value['profile'], profile)
    require(value['schema'] == 'hepta.service_artifact.installed-worker-terminal.v2',
            'explicit terminal observation schema differs')
    lost = label == 'lost-put-ACK'
    require(set(value) == {'schema', 'profile', 'injection_observed', 'close_attempts',
            'close_returns', 'primary_notes', 'cleanup_notes', 'terminal_calls', 'facts'},
            'terminal observation has an undeclared/missing field')
    require(value['injection_observed'] is lost, 'actual injection presence differs')
    if profile['version'] == 1:
        require(all(type(value[name]) is int and value[name] == 0 for name in (
                    'close_attempts', 'close_returns', 'primary_notes', 'cleanup_notes', 'terminal_calls'))
                and value['facts'] is None and b'HIA_WORKER_DELIVERY_UNKNOWN' not in stderr,
                'old uncaught worker contract was relabeled as terminal v2')
        return
    request = label in ('first', 'replay', 'lost-put-ACK', 'unknown-replay')
    for name, expected in (
            ('close_attempts', int(request)), ('close_returns', int(request and not lost)),
            ('primary_notes', int(lost)), ('cleanup_notes', int(lost)),
            ('terminal_calls', int(lost))):
        require(type(value[name]) is int and value[name] == expected,
                'terminal close/note/exit boundary count differs: ' + name)
    if not lost:
        require(value['facts'] is None and b'HIA_WORKER_DELIVERY_UNKNOWN' not in stderr,
                'healthy/refused request invented native delivery loss')
        return
    facts = value['facts']
    expected_true = {
        'request_observer_inactive', 'origin_present', 'origin_custodied', 'origin_loss_is_self',
        'origin_error_is_actual_injected', 'origin_native_pending', 'service_artifact_frame_retained',
        'primary_is_actual_worker_call_failure', 'primary_is_service_artifact_unknown',
        'primary_cause_is_actual_origin_error', 'cleanup_is_actual_close_failure',
        'cleanup_is_delivery_unknown', 'cleanup_context_is_primary', 'terminal_is_cleanup',
        'diagnostics_preserved_error_and_custody_identities'}
    require(set(facts) == expected_true | {'origin_retired', 'returned_status'},
            'terminal actual-identity observation fields differ')
    require(all(facts[name] is True for name in expected_true)
            and facts['origin_retired'] is False
            and type(facts['returned_status']) is int and facts['returned_status'] == 2,
            'actual primary/cleanup/origin/diagnostic identity differs')
    lines = stderr.splitlines()
    require(all(lines.count(marker) == 1 for marker in (
            b'HIA_WORKER_DELIVERY_UNKNOWN', b'REQUEST_PRIMARY_EXCEPTION', b'REQUEST_CLEANUP_EXCEPTION')),
            'complete real primary and cleanup diagnostics absent/repeated')
    require(b'REQUEST_TERMINAL_EXCEPTION' not in lines and b'diagnostic unavailable' not in stderr,
            'unexpected terminal error or unavailable diagnostic')
    for message in (
            b'ValueError: actual handler PUT acknowledgement lost after confirmed Store',
            b'ServiceArtifactUnknown: native service artifact observation failed',
            b'NativeDeliveryUnknown: resource has unconfirmed native delivery; it cannot be retired'):
        require(message in stderr, 'actual causal failure diagnostic absent')


class Captures:
    """Independent complete byte capture and terminal reread."""
    def __init__(self):
        self.records = {}

    def raw(self, path):
        path = Path(path)
        raw = regular_bytes(path)
        if path in self.records and self.records[path] != raw:
            raise ValueError('independent terminal source changed between reads')
        self.records[path] = raw
        return raw

    def stable(self):
        for path, raw in self.records.items():
            require(regular_bytes(path) == raw, 'independent terminal source changed at completion')


def read_installation(source_root, directory):
    """Read all four complete worker captures; do not execute or import product."""
    root, directory = Path(source_root).resolve(), Path(directory).resolve()
    captured = Captures()
    authority = admit_source_authority(captured, root)
    profile = authority['worker_profile']
    raw_installation = captured.raw(directory / 'installation.json')
    installation = json.loads(raw_installation, object_pairs_hook=unique_pairs)
    equal(installation['terminal_source_authority'], authority)
    installed, wheel = Path(installation['installed']).resolve(), Path(installation['wheel']).resolve()
    require(installed.is_relative_to(directory) and wheel.is_relative_to(directory),
            'installed worker artifacts are outside the original case directory')
    require(sha256(captured.raw(wheel)).hexdigest() == installation['wheel_sha256'], 'wheel bytes changed')
    equal(digest(captured.raw(installed / 'hepta/hia_agent_worker.py')), profile['worker'])
    records = tuple(installed.glob('*.dist-info/RECORD'))
    require(len(records) == 1, 'installed RECORD inventory differs')
    require(sha256(captured.raw(records[0])).hexdigest() == installation['installed_RECORD_sha256'],
            'installed RECORD changed')
    bundle = directory / 'bundle.json'
    require(sha256(captured.raw(bundle)).hexdigest() == installation['bundle_sha256'], 'helper bundle changed')
    module = ast.parse(captured.raw(root / 'tests/test_hia_service_artifact_native.py'))
    cls, = [node for node in module.body if isinstance(node, ast.ClassDef) and node.name == 'ServiceArtifactNativeTests']
    method, = [node for node in cls.body if isinstance(node, ast.FunctionDef)
               and node.name == 'test_actual_installed_worker_and_durable_parent_ACK_loss']
    scripts = [node.value.value for node in ast.walk(method) if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == 'script' and isinstance(node.value, ast.Constant)
               and type(node.value.value) is str]
    require(len(scripts) == 1, 'complete actual installed worker script differs')
    labels = ('first', 'replay', 'lost-put-ACK', 'unknown-replay')
    keys = ('success', 'replay', 'lost_put_ack', 'unknown_replay')
    require(set(installation['observations']) == set(keys), 'complete four worker records are required')
    rows, roots = {}, {}
    for label, key in zip(labels, keys):
        stdout = captured.raw(directory / (label + '.stdout'))
        stderr = captured.raw(directory / (label + '.stderr'))
        command_raw = captured.raw(directory / (label + '-command.json'))
        command = json.loads(command_raw, object_pairs_hook=unique_pairs)
        require(set(command) == {'command', 'timeout_seconds'}
                and type(command['timeout_seconds']) is int and command['timeout_seconds'] == 60,
                'original worker deadline changed')
        argv = command['command']
        require(type(argv) is list and len(argv) == 17 and all(type(item) is str for item in argv)
                and argv[1:5] == ['-B', '-I', '-c', scripts[0]]
                and argv[5:8] == [str(installed), 'lost_put_ack' if label == 'lost-put-ACK' else 'normal', str(root)]
                and argv[8] == '--state-root' and argv[10] == '--artifact-root'
                and argv[12:14] == ['--request-json-stdin', '--native-helpers-manifest']
                and argv[14:17] == [str(bundle), '--expected-native-helpers-sha256', installation['bundle_sha256']],
                'actual installed worker command differs from the fixed complete script')
        roots[label] = argv[9], argv[11]
        process_raw = captured.raw(directory / (label + '-terminal-process.json'))
        process = json.loads(process_raw, object_pairs_hook=unique_pairs)
        require(process_raw == canonical(process) + b'\n', 'complete terminal process record bytes differ')
        expected_exit = profile['lost_ack_exit'] if label == 'lost-put-ACK' else 0
        equal(process, {'returncode': expected_exit, 'stdout': digest(stdout), 'stderr': digest(stderr),
                        'command': digest(command_raw)})
        prefix = b'SERVICE_ARTIFACT_COUNTS='
        lines = [line[len(prefix):] for line in stderr.splitlines() if line.startswith(prefix)]
        require(len(lines) == 1, 'actual worker counts are missing or duplicated')
        counts = json.loads(lines[0], object_pairs_hook=unique_pairs)
        observation = installation['observations'][key]
        equal(observation['counts'], counts)
        verify_terminal(counts['terminal'], stderr, label, profile)
        if label == 'lost-put-ACK':
            require(stdout == b'', 'unknown request emitted a successful report')
            require(type(observation['worker_exit']) is int and observation['worker_exit'] == expected_exit,
                    'actual unknown return code differs')
        else:
            equal(json.loads(stdout, object_pairs_hook=unique_pairs), observation['report'])
        rows[label] = {'returncode': expected_exit, 'terminal': counts['terminal'],
                       'stdout': digest(stdout), 'stderr': digest(stderr), 'command': digest(command_raw)}
    equal(roots['first'], roots['replay'])
    equal(roots['lost-put-ACK'], roots['unknown-replay'])
    require(roots['first'] != roots['lost-put-ACK'], 'independent prepared requests were aliased')
    captured.stable()
    return {'schema': 'hepta.service_artifact.worker-terminal-readback.v2',
            'status': 'PASS_COMPLETE_FOUR_WORKER_TERMINALS', 'source_authority': authority,
            'workers': rows, 'captured_files': {str(path): digest(raw) for path, raw in captured.records.items()},
            'raw_source_and_capture_unchanged': True, 'original_business_assertions_owned_by_Native8': True,
            'finite146_qualified_by_this_reader': False, 'whole_native_stack_qualified': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = read_installation(args.root, args.installation)
    with args.output.open('xb') as stream:
        stream.write(canonical(result) + b'\n')
    print(result['status'])
