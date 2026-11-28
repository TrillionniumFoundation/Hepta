"""Compare the complete HIA service with the frozen rmcp process at the wire boundary.

The corpus is frozen independently of production schema/generator imports. This
is an envelope/framing gate; accepted business jobs need the public campaign.
Both complete stdout/stderr streams and configuration inputs are retained.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import time
import traceback

FIXTURES = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
CASES_SHA256 = '2b0b8b4d0df13384ee99d0809449748ef24c0c26931c9c8636b8892e2ca6b2e8'
PROFILES_SHA256 = 'c449aec12a7fd41d5b46af7cb4348ddf61a29743c2c635330633a25ca96348f3'
REFERENCE_SHA256 = 'beb253af13ab729bd8c25c96f2d4b80a2c931c905ad33559ef8997f4cabf43c7'
LINE_LIMIT = 16 << 20


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def wire(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def framing_cases():
    init = wire({'jsonrpc': '2.0', 'id': 'init', 'method': 'initialize', 'params': {
        'protocolVersion': '2025-11-25', 'capabilities': {},
        'clientInfo': {'name': 'framing-qualification', 'version': '1'}}})
    ready = wire({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
    ping = wire({'jsonrpc': '2.0', 'id': 'ping', 'method': 'ping'})
    oversized = wire({'jsonrpc': '2.0', 'id': 'oversized', 'method': 'ping'})
    prefix = init + ready
    for size in (8 << 20, (8 << 20) + 2, LINE_LIMIT):
        yield f'line-{size}-bytes-including-newline', prefix + b' ' * (size - len(ping)) + ping, ['init', 'ping']
    yield 'oversize-line-discard-and-recover', prefix + b' ' * (LINE_LIMIT + 1 - len(oversized)) + oversized + ping, ['init', 'ping']
    yield 'undelimited-eof-is-discarded', prefix + ping[:-1], ['init']
    yield 'crlf-frames', (prefix + ping).replace(b'\n', b'\r\n'), ['init', 'ping']
    yield 'initial-utf8-bom-negotiation-refused', b'\xef\xbb\xbf' + prefix + ping, ['init']
    yield 'empty-lines-and-recovery', prefix + b'\n\r\n \n' + ping, ['init', 'ping']



def control_cases():
    controls = [
        ('prompts/list', {}), ('prompts/list', {'cursor': 17}),
        ('resources/subscribe', {'uri': 'missing'}),
        ('resources/unsubscribe', {'uri': 'missing'}),
        ('completion/complete', {'ref': {'type': 'ref/resource', 'uri': 'x'},
                                 'argument': {'name': 'x', 'value': 'a'}}),
        ('completion/complete', {'ref': {'type': 'ref/prompt', 'name': 'x'},
                                 'argument': {'name': 'x', 'value': 'a'},
                                 'context': {'arguments': {'x': 'v'}}}),
        ('completion/complete', {'ref': ['ref/resource', 'x'],
                                 'argument': ['x', 'a']}),
        ('completion/complete', {'ref': {'type': 'invalid', 'uri': 'x'},
                                 'argument': {'name': 'x', 'value': 'a'}}),
        ('resources/read', {'uri': 'missing'}),
        ('resources/read', {'uri': 'octofs://jobs/missing'}),
        ('resources/read', {'uri': 'octofs://jobs/'}),
        ('ping', {}), ('server/discover', {}),
    ]
    for version in ('2025-11-25', '2026-07-28'):
        init = wire({'jsonrpc': '2.0', 'id': 'init', 'method': 'initialize', 'params': {
            'protocolVersion': version, 'capabilities': {},
            'clientInfo': {'name': 'control-qualification', 'version': '1'}}})
        ready = wire({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        for index, (method, params) in enumerate(controls):
            params = dict(params)
            if version == '2026-07-28':
                params['_meta'] = {'io.modelcontextprotocol/protocolVersion': version,
                                   'io.modelcontextprotocol/clientCapabilities': {}}
            request = wire({'jsonrpc': '2.0', 'id': index, 'method': method, 'params': params})
            yield 'control/' + version + '/' + str(index) + '/' + method, init + ready + request, ['init', index]


def messages_equal(left, right, profiles):
    if len(left) != len(right):
        return False
    for reference, native in zip(left, right, strict=True):
        result = reference.get('result')
        if isinstance(result, dict) and 'protocolVersion' in result:
            other = native.get('result')
            if not isinstance(other, dict) or 'protocolVersion' not in other:
                return False
            for actual, name in ((result, 'reference'), (other, 'native')):
                expected = profiles[name + '_initialization_profile']
                if {k: v for k, v in actual.items() if k != 'protocolVersion'} != {
                        k: v for k, v in expected.items() if k != 'protocolVersion'}:
                    return False
            if result['protocolVersion'] != other['protocolVersion']:
                return False
            if {k: v for k, v in reference.items() if k != 'result'} != {
                    k: v for k, v in native.items() if k != 'result'}:
                return False
        elif isinstance(result, dict) and 'supportedVersions' in result:
            other = native.get('result')
            if result != profiles['reference_discovery_profile'] or other != profiles['native_discovery_profile']:
                return False
            if {k: v for k, v in reference.items() if k != 'result'} != {
                    k: v for k, v in native.items() if k != 'result'}:
                return False
        elif reference != native:
            return False
    return True


def correlated_messages_equal(left, right, profiles):
    """Compare pipelined independent responses without imposing completion order.

    rmcp 3.9.0 dispatches response tasks concurrently (service.rs JoinSet).
    Initialization must still be first. Every other complete message, including
    its ID and errors and duplicate multiplicity, must be byte-value equivalent.
    """
    def initialization_indexes(messages):
        return [index for index, value in enumerate(messages)
                if isinstance(value.get('result'), dict) and 'protocolVersion' in value['result']]
    left_init, right_init = initialization_indexes(left), initialization_indexes(right)
    if left_init != right_init or left_init not in ([], [0]):
        return False
    if left_init:
        if not messages_equal(left[:1], right[:1], profiles):
            return False
        left, right = left[1:], right[1:]
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return Counter(map(encode, left)) == Counter(map(encode, right))


def compare_case(name, left, right, profiles, expected_ids=None):
    if 'messages' not in left or 'messages' not in right or left['returncode'] != right['returncode']:
        return False
    compare = correlated_messages_equal if name.startswith('stream/') else messages_equal
    return compare(left['messages'], right['messages'], profiles) and (
        expected_ids is None or all([msg.get('id') for msg in side['messages']] == expected_ids
                                  for side in (left, right)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', type=Path, required=True)
    parser.add_argument('--service-sha256', required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--framing-only', action='store_true')
    selection.add_argument('--stream-controls-only', action='store_true')
    args = parser.parse_args()
    paths = {'reference': args.reference.resolve(), 'native': args.service.resolve(),
             'manifest': args.manifest.resolve(), 'config': args.config.resolve()}
    pins = {'reference': REFERENCE_SHA256, 'native': args.service_sha256,
            'manifest': args.manifest_sha256, 'config': digest(paths['config'])}
    for name, path in paths.items():
        assert digest(path) == pins[name], ('input pin mismatch', name)
    raw_cases = (FIXTURES / 'hia_mcp_sdk_wire_cases.json').read_bytes()
    assert sha256(raw_cases).hexdigest() == CASES_SHA256
    profiles_path = FIXTURES / 'hia_mcp_sdk_wire_profiles.json'
    assert digest(profiles_path) == PROFILES_SHA256
    profiles = json.loads(profiles_path.read_bytes())
    assert profiles['reference_runtime_sha256'] == REFERENCE_SHA256
    source_cases = json.loads(raw_cases)
    assert len(source_cases) == profiles['count'] == 1050
    cases = [] if args.framing_only or args.stream_controls_only else [(c['name'], bytes.fromhex(c['hex']) + b'\n', None) for c in source_cases]
    cases.extend(framing_cases())
    if not args.framing_only:
        from tests.hia_mcp_stream_cases import cases as original_stream_cases
        cases.extend(("stream/" + name, raw, None) for name, raw in original_stream_cases())
        cases.extend(control_cases())
    output = args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    baseline = json.loads(paths['config'].read_bytes())
    env = {k: v for k, v in os.environ.items() if not k.startswith((
        'HEPTA_HIA_', 'HIA_LOCAL_MCP_', 'HIA_TRANSPORT_', 'HEPTA_EFFECT_OWNER_'))}
    env['RUST_LOG'] = 'warn'
    report = {'schema': 'HIA_MCP_SERVICE_PROTOCOL_V1', 'phase': 'running',
              'scope': 'complete-process typed envelopes and stream framing before business dispatch',
              'comparison': profiles['comparison'], 'profiles': profiles, 'pins': pins,
              'qualifier_sha256': digest(Path(__file__)), 'expected_count': len(cases),
              'stream_corpus_sha256': digest(FIXTURES.parent / 'hia_mcp_stream_cases.py'),
              'started': datetime.now(timezone.utc).isoformat()}
    rows = []

    def save():
        report.update(count=len(rows), failed=sum(not row['passed'] for row in rows))
        (output / 'status.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(item):
        index, (name, raw, expected_ids) = item
        case = output / f'{index:04d}'
        case.mkdir(mode=0o700)
        (case / 'input.bin').write_bytes(raw)
        row = {'index': index, 'name': name, 'input_sha256': sha256(raw).hexdigest(),
               'expected_ids': expected_ids, 'timeout_seconds': 90 if name.startswith('stream/') else 15}
        for kind in ('reference', 'native'):
            cfg = json.loads(json.dumps(baseline))
            cfg['state_dir'] = str(case / (kind + '-state'))
            cfg['controller_workspace_roots'] = [str(output)]
            config = case / (kind + '-config.json')
            config.write_text(json.dumps(cfg))
            config.chmod(0o600)
            cmd = ([str(paths[kind]), 'mcp', '--path', str(output), '--runtime-config', str(config),
                    '--hia-controller-manifest', str(paths['manifest']),
                    '--hia-controller-sha256', pins['manifest']] if kind == 'reference' else
                   [str(paths[kind]), str(config), digest(config), str(paths['manifest']), pins['manifest']])
            started = time.monotonic()
            try:
                process = subprocess.run(cmd, input=raw, capture_output=True, timeout=row['timeout_seconds'],
                    cwd=case, env={**env, 'PATH': '/usr/bin' if kind == 'reference' else ''})
                (case / (kind + '.stdout')).write_bytes(process.stdout)
                (case / (kind + '.stderr')).write_bytes(process.stderr)
                row[kind] = {'returncode': process.returncode,
                    'messages': [json.loads(line) for line in process.stdout.splitlines()],
                    'seconds': time.monotonic() - started, 'stderr_bytes': len(process.stderr)}
            except subprocess.TimeoutExpired as error:
                (case / (kind + '.stdout')).write_bytes(error.stdout or b'')
                (case / (kind + '.stderr')).write_bytes(error.stderr or b'')
                row[kind] = {'timeout': True}
        left, right = row['reference'], row['native']
        row['ordered_response_match'] = ('messages' in left and 'messages' in right and
            messages_equal(left['messages'], right['messages'], profiles))
        row['comparison'] = 'exact correlated pipelined responses' if name.startswith('stream/') else 'exact ordered responses'
        row['passed'] = compare_case(name, left, right, profiles, expected_ids)
        return row

    save()
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(run, item) for item in enumerate(cases)]
            with (output / 'results.jsonl').open('x') as result_file:
                for future in as_completed(futures):
                    row = future.result()
                    rows.append(row)
                    result_file.write(json.dumps(row) + '\n')
                    result_file.flush()
                    if not row['passed']:
                        print('DIFFERENCE', json.dumps({key: row[key] for key in ('index', 'name', 'passed', 'ordered_response_match')}), flush=True)
                    if len(rows) % 25 == 0:
                        save()
                        print('PROGRESS', len(rows), 'of', len(cases), 'differences', report['failed'], flush=True)
        for name, path in paths.items():
            assert digest(path) == pins[name], ('input changed', name)
        report.update(phase='completed', passed=all(row['passed'] for row in rows),
                      finished=datetime.now(timezone.utc).isoformat())
        save()
        (output / 'qualification.json').write_text(json.dumps(
            {**report, 'cases': sorted(rows, key=lambda row: row['index'])}, indent=2) + '\n')
        print('COMPLETE', json.dumps(report), flush=True)
        return 0 if report['passed'] else 1
    except BaseException:
        report.update(phase='failed', error=traceback.format_exc())
        save()
        raise


if __name__ == '__main__':
    raise SystemExit(main())
