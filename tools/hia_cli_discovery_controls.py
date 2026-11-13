"""Portable versions of all frozen R5 observations, with their original limits.

These are observers and independent reference oracles. The isolated native child
imports zero project modules; it cannot call these Python semantic oracles.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback
import zlib

ROOT = Path(__file__).resolve().parents[1]
CHILD = ROOT / 'tools/hia_cli_discovery_child.py'
MAGIC = int.from_bytes(b'HCLJSON1', 'little')
WORK_BYTES = 131072
VM_LABELS = ('capabilities-exact', 'catalog-v1-exact', 'catalog-v8-exact',
             'catalog-v8-short-0', 'unknown-schema-8', 'short-work-131071')
SCHEMAS = tuple('hepta.hia.program.v' + str(i) for i in range(1, 9))


def digest(raw):
    return sha256(raw).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def wire(operation=2, schema=None):
    return struct.pack('<4Q', MAGIC, operation, int(schema is not None),
                       0 if schema is None else len(schema)) + (b'' if schema is None else schema)


def original_oracles():
    from hepta import cli
    from hepta.hia_opcodes import opcode_catalog
    from hepta.hia_schema import PRIMITIVE_PROFILES
    if tuple(PRIMITIVE_PROFILES) != SCHEMAS:
        raise ValueError('the original eight-schema oracle domain changed')
    def pretty(value):
        return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    rows = [('capabilities', wire(1), pretty(cli.agent_capabilities()))]
    rows.extend(('catalog-v' + name[-1], wire(2, name.encode()), pretty(opcode_catalog(name)))
                for name in PRIMITIVE_PROFILES)
    rows.append(('catalog-default', wire(), pretty(opcode_catalog())))
    return rows


def cases(oracles):
    rows = []
    for label, request, data in oracles:
        rows.append((label + '-exact', request, len(data), WORK_BYTES, None, data, False, 0x5a))
        rows.append((label + '-tail', request, len(data) + 37, WORK_BYTES, None, data, False, 0xc3))
        for extent in (0, len(data) - 1):
            rows.append((label + '-short-' + str(extent), request, extent, WORK_BYTES,
                         4294967294, None, False, 0x5a))
    bad = [('empty', b'', 4294967295), ('truncated', wire()[:31], 4294967295),
           ('bad-magic', bytes(8) + wire()[8:], 4294967295), ('bad-op', wire(0), 4294967295),
           ('mode2', struct.pack('<4Q', MAGIC, 2, 2, 0), 4294967295),
           ('length-max', struct.pack('<4Q', MAGIC, 2, 1, (1 << 64) - 1), 4294967295),
           ('trailing', wire() + b'x', 4294967295),
           ('cap-schema', wire(1, b'hepta.hia.program.v8'), 4294967295),
           ('none-payload', struct.pack('<4Q', MAGIC, 2, 0, 1) + b'x', 4294967295)]
    for index, value in enumerate((b'', b'bad', b'hepta.hia.program.v0', b'hepta.hia.program.v9',
            b'hepta.hia.program.v88', b'hepta.hia.composite.v1', b'Hepta.hia.program.v8',
            b'hepta.hia.program.v8\0', b'\xff' * 20)):
        bad.append(('unknown-schema-' + str(index), wire(2, value), 4294967293))
    rows.extend((label, request, 512, WORK_BYTES, status, None, True, 0x5a)
                for label, request, status in bad)
    rows.extend(('short-work-' + str(extent), wire(), 512, extent, 4294967292, None, True, 0x5a)
                for extent in (0, 1, WORK_BYTES - 1))
    if len(rows) != 61 or len({row[0] for row in rows}) != 61:
        raise AssertionError('all original 61 observations must remain distinct')
    return rows


def native_controls(output, image, *, guard=lambda: None):
    output, image = Path(output), Path(image).resolve(strict=True)
    output.mkdir(mode=0o700)
    image_raw, child_raw = image.read_bytes(), CHILD.read_bytes()
    oracles = original_oracles()
    expected = cases(oracles)
    retained = json.loads((ROOT / 'tests/fixtures/hia_cli_discovery_r5_cases.json').read_bytes())
    retained_rows = {row['label']: row for row in retained['rows']}
    assert list(retained_rows) == [row[0] for row in expected]
    oracle_dir = output / 'oracles'
    oracle_dir.mkdir()
    for label, _request, raw in oracles:
        (oracle_dir / (label + '.json')).write_bytes(raw)
    report = {'schema': 'hepta.hia.cli-discovery-json-native-controls.v1',
              'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY', 'status': 'FAIL',
              'image_sha256': digest(image_raw), 'child_sha256': digest(child_raw),
              'expected_labels': [row[0] for row in expected], 'expected_count': 61,
              'child_seconds': 20, 'rows': [], 'failures': []}
    try:
        for label, request, outlen, worklen, expected_status, expected_bytes, guard_all, fill in expected:
            guard()
            folder = output / label
            folder.mkdir()
            canary = b'\x9d' * 64
            before = [canary + request + canary, canary + b'\xa5' * outlen + canary,
                      canary + bytes([fill]) * worklen + canary]
            buffers = []
            for name, raw, extent in zip(('source', 'output', 'workspace'), before, (len(request), outlen, worklen)):
                path = folder / (name + '.shared')
                path.write_bytes(raw)
                (folder / (name + '.before')).write_bytes(raw)
                buffers.append({'path': str(path.absolute()), 'bytes': len(raw),
                                'sha256': digest(raw), 'extent': extent})
            req = {'schema': 'hia.cli-discovery.native-request.v1', 'image': str(image),
                   'image_sha256': digest(image_raw), 'buffers': buffers,
                   'report': str((folder / 'CHILD.json').absolute())}
            request_path = folder / 'REQUEST.json'
            save(request_path, req)
            command = [sys.executable, '-I', '-S', '-B', str(CHILD),
                       str(request_path.absolute()), digest(request_path.read_bytes())]
            row = {'label': label, 'status': 'FAIL', 'timed_out': False,
                   'request_sha256': digest(request), 'output_extent': outlen,
                   'workspace_extent': worklen, 'fill': fill}
            started = time.monotonic_ns()
            try:
                process = subprocess.run(command, cwd=folder,
                    env={'PATH': os.defpath, 'LC_ALL': 'C.UTF-8'}, capture_output=True, timeout=20)
                (folder / 'stdout.raw').write_bytes(process.stdout)
                (folder / 'stderr.raw').write_bytes(process.stderr)
                row['returncode'] = process.returncode
                after = [Path(item['path']).read_bytes() for item in buffers]
                row.update(canaries_unchanged=all(raw[:64] == canary and raw[-64:] == canary for raw in after),
                           source_unchanged=after[0] == before[0], output_sha256=digest(after[1]),
                           workspace_sha256=digest(after[2]))
                child = json.loads((folder / 'CHILD.json').read_bytes())
                row['child'] = child
                assert process.returncode == 0, (process.returncode, process.stderr)
                assert row['canaries_unchanged'] and row['source_unchanged']
                assert child['forbidden_project_modules_loaded'] == []
                assert type(child['actual_native_entries']) is int and child['actual_native_entries'] == 1
                assert child['image_sha256'] == digest(image_raw)
                assert child['request_sha256'] == digest(request_path.read_bytes())
                assert type(child['result']) is int
                old = retained_rows[label]
                assert old['request_hex'] == request.hex()
                assert (old['output_extent'], old['workspace_extent'], old['fill']) == (outlen, worklen, fill)
                assert old['result'] == child['result']
                assert old['output_sha256'] == row['output_sha256']
                assert old['workspace_sha256'] == row['workspace_sha256']
                if expected_status is not None:
                    assert child['result'] == expected_status, (child['result'], expected_status)
                data = after[1][64:-64]
                if expected_bytes is not None:
                    assert child['result'] == len(expected_bytes), (child['result'], len(expected_bytes))
                    assert data[:len(expected_bytes)] == expected_bytes
                    assert data[len(expected_bytes):] == b'\xa5' * (outlen - len(expected_bytes))
                else:
                    assert after[1] == before[1], 'rejected output changed'
                if guard_all:
                    assert after == before, 'preflight changed a buffer'
                guard()
                assert image.read_bytes() == image_raw and CHILD.read_bytes() == child_raw
                row['status'] = 'MATCH'
            except subprocess.TimeoutExpired as error:
                row.update(timed_out=True, traceback=traceback.format_exc())
                (folder / 'stdout.raw').write_bytes(error.stdout or b'')
                (folder / 'stderr.raw').write_bytes(error.stderr or b'')
            except BaseException:
                row['traceback'] = traceback.format_exc()
            row['wall_ns'] = time.monotonic_ns() - started
            if row['status'] != 'MATCH':
                report['failures'].append(label)
            report['rows'].append(row)
            save(folder / 'RESULT.json', row)
            save(output / 'REPORT.json', report)
        from hepta.hia_opcodes import opcode_catalog, OpcodeRejected
        errors = {}
        for value in ('', 'bad', 'hepta.hia.program.v0', 'hepta.hia.program.v9', 'hepta.hia.composite.v1'):
            try:
                opcode_catalog(value)
            except OpcodeRejected as error:
                errors[value] = {'type': type(error).__name__, 'message': str(error), 'code': error.code}
            else:
                raise AssertionError('original accepted invalid schema')
        report['original_unknown_schema_error'] = errors
        report['actual_native_entries'] = sum(row.get('child', {}).get('actual_native_entries', 0)
                                               for row in report['rows'])
        assert len(report['rows']) == 61 and report['actual_native_entries'] == 61
        assert not report['failures'], report['failures']
        report['status'] = 'PASS'
    finally:
        report['image_and_child_unchanged'] = image.read_bytes() == image_raw and CHILD.read_bytes() == child_raw
        if not report['image_and_child_unchanged']:
            report['status'] = 'FAIL'
        save(output / 'REPORT.json', report)
    return report


def packed(raw):
    return {'bytes': len(raw), 'sha256': digest(raw), 'encoding': 'base64-zlib',
            'data': base64.b64encode(zlib.compress(raw, 6)).decode()}


def vm_controls(output, native, *, guard=lambda: None):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    from hepta.hia_cli_discovery_json_native import SOURCE
    output, native = Path(output), Path(native)
    output.mkdir(mode=0o700)
    source = SOURCE.read_bytes()
    program = assemble_program(source)
    report = {'schema': 'hepta.hia.cli-discovery-json-vm-controls.v1',
              'scope': 'INDEPENDENT_ORDINARY_CORE_VM_NOT_COLD_AUTHORITY', 'status': 'FAIL',
              'source_sha256': digest(source), 'max_steps': 10000000,
              'max_heap_bytes': 8 << 20, 'max_call_depth': 128,
              'expected_labels': list(VM_LABELS), 'expected_count': 6, 'rows': []}
    try:
        for label in VM_LABELS:
            guard()
            folder = native / label
            expected = json.loads((folder / 'RESULT.json').read_bytes())
            request = json.loads((folder / 'REQUEST.json').read_bytes())
            assert expected['status'] == 'MATCH'
            actual = [Path(item['path']).read_bytes()[64:-64] for item in request['buffers']]
            before = [actual[0], b'\xa5' * request['buffers'][1]['extent'],
                      bytes([expected['fill']]) * request['buffers'][2]['extent']]
            owners = [_Owner(i, bytearray(raw)) for i, raw in enumerate(before)]
            machine = _Machine(program, 10000000, 8 << 20, None, 128)
            row = {'label': label, 'status': 'FAIL',
                   'before': dict(zip(('source', 'output', 'workspace'), map(packed, before)))}
            started = time.monotonic_ns()
            try:
                returned = machine.invoke(machine.functions['f0'],
                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])
                after = [bytes(owner.data) for owner in owners]
                row.update(result=returned, steps=machine.steps,
                           after=dict(zip(('source', 'output', 'workspace'), map(packed, after))))
                assert returned == [expected['child']['result']] or returned == (expected['child']['result'],)
                assert after == actual, [i for i, (a, b) in enumerate(zip(after, actual)) if a != b]
                guard()
                row['status'] = 'MATCH'
            except BaseException:
                row.update(traceback=traceback.format_exc(), steps=machine.steps,
                           after=dict(zip(('source', 'output', 'workspace'),
                                          map(packed, [bytes(owner.data) for owner in owners]))))
            row['wall_ns'] = time.monotonic_ns() - started
            save(output / (label + '.json'), row)
            report['rows'].append({k: v for k, v in row.items() if k not in ('before', 'after')})
            save(output / 'REPORT.json', report)
        assert len(report['rows']) == 6 and all(row['status'] == 'MATCH' for row in report['rows'])
        report['status'] = 'PASS'
    finally:
        report['source_unchanged'] = SOURCE.read_bytes() == source
        if not report['source_unchanged']:
            report['status'] = 'FAIL'
        save(output / 'REPORT.json', report)
    return report
