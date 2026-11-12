"""Independent, exact-operation reader for the third Core v2 native run.

Reads an already saved GitHub job log only. It does not import project code,
run products, or infer qualification from custody. Python integers preserve the
original nanosecond identity values. Reconstructed RESULT/manifest text is
explicitly labelled derived until separately joined to actual artifact bytes.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path
import re

PREFIX = 'HIA_CORE_EMITTER_SMALL_'
FRAME = 8192
MAX_RAW = 512 << 10
MAX_OUTPUT = 1 << 20
OPERATION = {
    'control_commit': '4b17b155ecd72c27e8300ffd778b837ce491cfdb',
    'workflow_commit': '6c0cf12e0c59a75cf4c1df84287a23840e38548f',
    'run_id': 0, 'run_attempt': 1,
    'policy_sha256': '8a76ca513d306c09587b215393abe62438b0fef8b328f7db282564e65400bc8c',
    'candidate': {'commit': '946f3fd08b63846305d3cbf920b61ceed1e696f0',
                  'tree': 'f3e2b8e3b638c830d2c8d4977e0972af32fee5bc', 'leaves': 4030},
}
STAGES = ('prepare', 'run-preparation', 'admit-preparation', 'run-tests', 'finalize')
FIXED = tuple('stage/' + stage + '.' + stream + '.log'
              for stage in STAGES for stream in ('stdout', 'stderr')) + (
    'context.json', 'PREPARED.json', 'preparation-setup.json', 'tests-setup.json',
    'PREPARATION-ACCEPTANCE.json', 'FINAL.json') + tuple(
    phase + '-guard/' + name for phase in ('preparation', 'tests')
    for name in ('request.json', 'guardian.json', 'child.stdout.log', 'child.stderr.log')) + (
    'preparation/report.json', 'preparation/final-HIA_SELFHOST_LANGUAGE_COVERAGE.json',
    'preparation/final-HIA_SELFHOST_CORE_SUPPORT.json', 'callers/report.json',
    'callers/component.unittest.log', 'callers/original-machine.unittest.log',
    'callers/original-core.unittest.log',
    'callers/component-fixture/installed-control/report.json',
    'callers/component-fixture/installed-control/processes.json',
    'callers/component-fixture/installed-control/installed-execution.stdout',
    'callers/component-fixture/installed-control/installed-execution.stderr')
DERIVED = 'derived/development-summary.json'
STDERR = 'diagnostic-control/full-diagnostics.stderr.log'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')

def loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda x: (_ for _ in ()).throw(ValueError('non-finite JSON')))

def encoded(kind, value):
    return (PREFIX + kind + ' ' + json.dumps(value, sort_keys=True,
            separators=(',', ':')) + '\n').encode('utf-8')

def gate(name):
    if name.startswith('preparation/'):
        return 'preparation'
    if name.startswith('callers/'):
        return 'tests'
    for phase in ('preparation', 'tests'):
        if name.startswith(phase + '-guard/') and not name.endswith('/request.json'):
            return phase
    return None

def decode(raw):
    require(type(OPERATION['run_id']) is int and OPERATION['run_id'] > 0, 'actual provider run identity not frozen')
    require(type(raw) is bytes and raw.endswith(b'\n'), 'complete log bytes required')
    records, clean = [], []
    for line in raw.decode('utf-8', errors='strict').splitlines(keepends=True):
        match = re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.]\d{1,9}Z (.*)\n', line)
        if not match or not match[1].startswith(PREFIX):
            continue
        body = (match[1] + '\n').encode('utf-8')
        kind, value_raw = match[1][len(PREFIX):].split(' ', 1)
        value = loads(value_raw)
        require(type(value) is dict and encoded(kind, value) == body, 'noncanonical frame')
        records.append((kind, value))
        clean.append(body)
    require(records and sum(map(len, clean)) <= MAX_OUTPUT, 'missing or oversized stream')
    cursor = 0
    def take(kind):
        nonlocal cursor
        require(cursor < len(records) and records[cursor][0] == kind,
                'missing/reordered/duplicate record: ' + kind)
        value = records[cursor][1]
        cursor += 1
        return value
    manifest = take('BEGIN')
    require(manifest.get('schema') == 'hia.core-emitter-native-small-diagnostic.v1', 'manifest schema')
    require({key: manifest.get(key) for key in OPERATION} == OPERATION, 'wrong operation')
    require(manifest.get('fixed_original_file_count') == len(FIXED) == 35
            and manifest.get('maximum_frame_raw_bytes') == MAX_RAW
            and manifest.get('maximum_stdout_bytes') == MAX_OUTPUT
            and manifest.get('frame_bytes') == FRAME, 'fixed limits or denominator differ')
    for key in ('all_35_originals_claimed_in_small_channel', 'native_or_cold_qualification_claimed',
                'qualification_validator_executed', 'product_execution', 'original_exit_status_modified'):
        require(manifest.get(key) is False, 'unsupported claim: ' + key)
    require(manifest.get('full_originals_and_full_stream_always_artifact') is True, 'custody scope differs')
    complete = manifest.get('full_stream_complete_and_bound')
    require(type(complete) is bool and manifest.get('status') ==
        ('BOUNDED_DIAGNOSTIC_CAPTURED' if complete else 'SMALL_DIAGNOSTIC_HOLD'), 'status differs')
    ledger = manifest.get('whole_file_ledger')
    require(type(ledger) is dict and set(ledger) >= set(FIXED)
            and set(ledger) <= set(FIXED) | {STDERR}, 'missing or extra ledger entries')
    closed = manifest.get('closed_current_phase_ECHILD')
    if complete:
        require(type(closed) is dict and set(closed) == {'preparation', 'tests'}
                and all(type(x) is bool for x in closed.values()), 'phase boundary differs')
    selected = manifest.get('selected_files')
    require(type(selected) is list and len(selected) <= 37, 'selected denominator')
    names = [r.get('name') for r in selected]
    require(len(names) == len(set(names)) and set(names) <= set(FIXED) | {DERIVED, STDERR},
            'duplicate or unapproved selected name')
    expected_priority = ['stage/finalize.stderr.log', 'stage/run-tests.stderr.log',
        'stage/run-preparation.stderr.log', 'stage/admit-preparation.stderr.log', 'stage/prepare.stderr.log',
        'tests-guard/child.stderr.log', 'preparation-guard/child.stderr.log', 'stage/finalize.stdout.log',
        'stage/run-tests.stdout.log', 'stage/run-preparation.stdout.log', 'stage/admit-preparation.stdout.log',
        'stage/prepare.stdout.log', 'tests-guard/guardian.json', 'preparation-guard/guardian.json',
        'FINAL.json', 'callers/report.json', 'preparation/report.json',
        'callers/component-fixture/installed-control/report.json',
        'callers/component-fixture/installed-control/installed-execution.stderr']
    ordering = [DERIVED] + expected_priority + [x for x in FIXED if x not in expected_priority] + [STDERR]
    require(names == sorted(names, key=ordering.index), 'selected priority changed')
    originals, frames = {}, 0
    for selected_pin in selected:
        require(set(selected_pin) == {'name', 'kind', 'bytes', 'sha256', 'git_blob_sha1'}, 'selected pin fields')
        name = selected_pin['name']
        require(selected_pin['kind'] == ('DERIVED_PROJECTION_NOT_AN_ORIGINAL' if name == DERIVED
                else 'COMPLETE_ORIGINAL'), 'derived/original distinction lost')
        size = selected_pin['bytes']
        require(type(size) is int and 0 <= size <= MAX_RAW, 'selected size')
        count = (size + FRAME - 1) // FRAME
        require(take('FILE_BEGIN') == {**selected_pin, 'frame_bytes': FRAME, 'frame_count': count},
                'file begin differs')
        parts, offset = [], 0
        for index in range(count):
            frame = take('FILE_FRAME')
            require(set(frame) == {'name', 'index', 'offset', 'bytes', 'sha256', 'base64'}
                and frame['name'] == name and type(frame['index']) is int and frame['index'] == index
                and type(frame['offset']) is int and frame['offset'] == offset
                and type(frame['bytes']) is int and frame['bytes'] == min(FRAME, size - offset), 'frame fields')
            chunk = base64.b64decode(frame['base64'], validate=True)
            require(base64.b64encode(chunk).decode('ascii') == frame['base64']
                    and len(chunk) == frame['bytes'] and sha256(chunk).hexdigest() == frame['sha256'],
                    'frame bytes differ')
            parts.append(chunk)
            offset += len(chunk)
            frames += 1
        body = b''.join(parts)
        wanted = {k: selected_pin[k] for k in ('bytes', 'sha256', 'git_blob_sha1')}
        require(pin(body) == wanted and take('FILE_END') == {'name': name, **wanted, 'frame_count': count},
                'whole file/end differs')
        if name == DERIVED:
            projected = loads(body)
            require(projected.get('kind') == 'DERIVED_PROJECTION_NOT_AN_ORIGINAL'
                    and projected.get('current_operation') == OPERATION
                    and projected.get('qualification_validator_executed') is False
                    and projected.get('native_or_cold_qualification_claimed') is False,
                    'derived summary attribution differs')
            require(manifest['derived_projection'] == {**wanted, 'status': 'DERIVED_PROJECTION_INCLUDED'},
                    'derived summary pin differs')
        else:
            record = ledger[name]
            require(record.get('small_channel_status') == 'WHOLE_ORIGINAL_SELECTED'
                    and {k: record.get(k) for k in wanted} == wanted, 'ledger selected pin differs')
            if name in FIXED:
                require(complete and record.get('full_channel_status') == 'COMPLETE_ORIGINAL_READ',
                        'unverified original selected')
                require(not gate(name) or closed[gate(name)], 'unclosed phase bytes disclosed')
                require(manifest['full_diagnostic']['terminal_accounting']['fixed_file_observations'].get(name)
                        == {'status': 'COMPLETE_ORIGINAL_READ', **wanted}, 'upstream terminal pin differs')
            else:
                require(record.get('full_channel_status') == 'DIAGNOSTIC_STDERR_READ'
                    and {k: manifest['full_diagnostic']['stderr_original'].get(k) for k in wanted} == wanted,
                    'diagnostic stderr pin differs')
        originals[name] = body
    total = sum(map(len, originals.values()))
    require(total <= MAX_RAW and sum(len(x) for n, x in originals.items() if n != DERIVED)
            == manifest.get('selected_original_raw_bytes'), 'raw byte accounting differs')
    terminal = take('END')
    require(cursor == len(records), 'records follow END')
    prefix = b''.join(clean[:-1])
    result = {k: v for k, v in terminal.items() if k != 'result_original'}
    require(result == {
        'schema': 'hia.core-emitter-native-small-diagnostic-result.v1',
        'status': manifest['status'], 'current_operation': OPERATION,
        'manifest_wire_pin': pin(wire(manifest)), 'selected_file_count': len(originals),
        'selected_frame_raw_bytes': total, 'prefix_stdout_bytes': len(prefix),
        'prefix_stdout_sha256': sha256(prefix).hexdigest(),
        'all_35_originals_claimed_in_small_channel': False,
        'native_or_cold_qualification_claimed': False, 'original_exit_status_modified': False,
    }, 'terminal fields/accounting differ')
    require(terminal.get('result_original') == pin(wire(result)), 'RESULT wire pin differs')
    for name in FIXED:
        require((name in originals) == (ledger[name].get('small_channel_status') == 'WHOLE_ORIGINAL_SELECTED'),
                'ledger selection disagrees')
    audit = {'schema': 'hia.core-emitter-native-independent-small-readback.v1',
        'status': 'EXACT_BOUNDED_CUSTODY_DECODED', 'current_operation': OPERATION,
        'log': pin(raw), 'small_stream': pin(b''.join(clean)),
        'selected_file_count': len(originals), 'frame_count': frames,
        'framed_raw_bytes': total, 'complete_original_count': len(originals) - int(DERIVED in originals),
        'complete_original_raw_bytes': sum(len(x) for n,x in originals.items() if n != DERIVED),
        'phase_closed': closed, 'files': selected,
        'result_text_is_reconstructed_not_claimed_original': True,
        'all_35_originals_recovered': False, 'product_or_cold_qualification': False}
    return originals, manifest, result, audit, b''.join(clean)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    originals, manifest, result, audit, stream = decode(args.log.read_bytes())
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, body in originals.items():
        target = args.output / 'files' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(body)
        require(target.read_bytes() == body, 'local original readback differs')
    for name, body in {'AUDIT.json': wire(audit), 'manifest.RECONSTRUCTED.json': wire(manifest),
                       'RESULT.RECONSTRUCTED.json': wire(result), 'small.stdout.log': stream}.items():
        with (args.output / name).open('xb') as handle:
            handle.write(body)
    print(json.dumps(audit, sort_keys=True))

if __name__ == '__main__':
    main()
