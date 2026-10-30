#!/usr/bin/env python3
"""Read every archived member and cross-check recorded counts; execute nothing."""
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import time


def verify(folder):
    started = time.monotonic_ns()
    folder = Path(folder)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    wire = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    manifest = json.loads((folder / 'MANIFEST.json').read_bytes())
    assert manifest['schema'] == 'hepta.rust-finite-heap.development-evidence.v1'
    encoded = (folder / manifest['archive']['name']).read_bytes()
    assert len(encoded) == manifest['archive']['bytes'] and digest(encoded) == manifest['archive']['sha256']
    compressed = base64.b64decode(b''.join(encoded.splitlines()), validate=True)
    assert len(compressed) == manifest['decoded_xz']['bytes'] and digest(compressed) == manifest['decoded_xz']['sha256']
    files = {}
    with tarfile.open(fileobj=io.BytesIO(compressed), mode='r:xz') as archive:
        for member in archive:
            assert member.isfile() and member.name not in files
            assert member.name in manifest['members'] and not Path(member.name).is_absolute()
            assert '..' not in Path(member.name).parts
            row = manifest['members'][member.name]
            assert member.size == row['bytes']
            data = archive.extractfile(member).read()
            assert len(data) == row['bytes'] and digest(data) == row['sha256']
            files[member.name] = data
    assert set(files) == set(manifest['members']) and len(files) == manifest['member_count']
    assert sum(map(len, files.values())) == manifest['uncompressed_member_bytes']
    summary_raw = (folder / 'SUMMARY.json').read_bytes()
    assert summary_raw == files['SUMMARY.json']
    assert digest(summary_raw) == manifest['summary']['sha256']
    summary = json.loads(summary_raw)
    assert summary['source_commit'] == manifest['source_commit']
    for row in summary['attempts']:
        data = files[row['attempt'] + '/execution.json']
        assert digest(data) == row['receipt_sha256']
        actual = json.loads(data)
        assert all(actual[k] == row[k] for k in ('argv', 'returncode', 'outer_wall_ns'))
        for stream in ('stdout', 'stderr'):
            content = files[row['attempt'] + '/' + stream]
            assert actual[stream] == {'bytes': len(content), 'sha256': digest(content)}
        for name, identity in actual['modified_sources'].items():
            content = files[row['attempt'] + '/source/' + name]
            assert identity == {'bytes': len(content), 'sha256': digest(content)}
    failed = [row['attempt'] for row in summary['attempts'] if row['returncode'] != 0]
    assert failed == ['003-first-differential', '004-expanded-differential']
    assert summary['recorded_subprocess_wall_ns_sum'] == sum(row['outer_wall_ns'] for row in summary['attempts'])
    rust_log = files['006-rust-suite/stdout'].decode()
    assert sum(map(int, re.findall(r'test result: ok\. (\d+) passed', rust_log))) == summary['final_rust']['tests'] == 116
    python_log = files['007-focused-regression/stderr'].decode()
    assert re.search(r'Ran 51 tests in [\d.]+s\n\nOK\s*$', python_log)
    actual = json.loads(files['007-focused-regression/raw/actual.json'])
    counts = summary['new_heap_differential']
    assert len(actual['processes']) == counts['actual_direct_rust_processes'] == 296
    assert len(actual['observations']) == counts['matched_bound_and_machine_observations'] == 253
    assert len(actual['refusals']) == counts['raw_refusal_controls'] == 28
    assert len(actual['isolated_child_processes']) == counts['isolated_python_child_processes'] == 1
    assert actual['executable_sha256'] == summary['binary']['sha256']
    responses = set()
    for process in actual['processes']:
        assert process['executable_sha256'] == summary['binary']['sha256']
        raw = actual['programs'][process['input_sha256']].encode()
        assert digest(raw) == process['input_sha256']
        assert type(process['outer_wall_ns']) is int and process['outer_wall_ns'] > 0
        if process['returncode'] == 0:
            assert process['stderr'] == ''
            responses.add(wire(json.loads(process['stdout'])))
    for observed in actual['observations']:
        assert observed['matched'] is True
        report = observed['rust_report']
        assert wire(report) in responses
        assert report['heap_bound']['peak_bound_bytes'] == observed['python_bound']['peak_bound_bytes']
        runtime = report['runtime']['execution']
        oracle = observed['python_execution']
        assert all(wire(runtime[k]) == wire(oracle[k]) for k in ('status', 'steps', 'resources'))
        assert wire(runtime['values']) == wire(oracle['values']) if runtime['status'] == 'returned' else runtime['error']['code'] == oracle['error']['code']
        assert runtime['resources']['peak_bytes'] <= report['heap_bound']['peak_bound_bytes']
    for refused in actual['refusals']:
        assert refused['returncode'] == 1 and not refused['stdout'] and refused['stderr'].startswith('E_HIA_')
    return {'verified': True, 'files_rehashed': len(files), 'counts': counts,
        'recorded_failed_attempts': failed, 'wall_ns': time.monotonic_ns() - started,
        'scope': 'archived byte/count/observed comparison consistency only; no program execution or renewed admission'}


if __name__ == '__main__':
    print(json.dumps(verify(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).parent), sort_keys=True))
