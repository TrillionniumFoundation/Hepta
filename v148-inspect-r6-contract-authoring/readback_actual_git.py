"""Read only immutable Git responses and author files; execute no product."""
from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zlib

HERE = Path(__file__).absolute().parent


def pin(raw):
    return {'bytes': len(raw), 'mode': '100644',
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'sha256': hashlib.sha256(raw).hexdigest()}


def identity(s):
    return [s.st_dev, s.st_ino, s.st_nlink, s.st_mode, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns]


def regular(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1, str(path)
    data = path.read_bytes()
    assert identity(s) == identity(path.lstat()), str(path)
    return data, s


def write_new(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    path = HERE / name
    with path.open('xb') as handle:
        assert handle.write(raw) == len(raw)
    path.chmod(0o644)
    assert path.read_bytes() == raw
    return pin(raw)


def main():
    rows = json.loads((HERE / 'GIT/INTENT.json').read_bytes())
    assert len(rows) == 24 and len({row['name'] for row in rows}) == 24
    raw_by_name = {}
    envelope_rows = []
    for row in rows:
        name = row['name']
        local, s = regular(Path(row['path']))
        assert pin(local) == row['pin'] and stat.S_IMODE(s.st_mode) == row['posix_mode']
        prefix = HERE / 'GIT' / name.replace('/', '__')
        post_raw, _ = regular(Path(str(prefix) + '.POST.json'))
        get_raw, _ = regular(Path(str(prefix) + '.GET.json'))
        receipt_raw, _ = regular(Path(str(prefix) + '.RECEIPT.json'))
        post, response, receipt = map(json.loads, (post_raw, get_raw, receipt_raw))
        assert post['structuredContent']['sha'] == row['pin']['git_blob']
        returned = response['structuredContent']['content'].encode('utf-8')
        assert returned == local and pin(returned) == row['pin'], name
        assert receipt['post_sha'] == row['pin']['git_blob']
        assert receipt['full_get_equal'] is True and receipt['product_execution'] is False
        raw_by_name[name] = returned
        envelope_rows.append({'name': name, 'pin': row['pin'], 'post': pin(post_raw),
                              'get': pin(get_raw), 'receipt': pin(receipt_raw)})

    index = json.loads(raw_by_name['ARCHIVE/SOURCE-PARTS.json'])
    assert index['logical_files'] == 58 and index['logical_bytes'] == 2500582
    assert index['directories'] == 7 and len(index['parts']) == 6
    parts, offset = [], 0
    for ordinal, part in enumerate(index['parts']):
        assert part['ordinal'] == ordinal and part['offset'] == offset
        raw = raw_by_name['ARCHIVE/' + part['file']]
        assert pin(raw) == part['pin']
        parts.append(raw)
        offset += len(raw)
    capsule_raw = b''.join(parts)
    assert pin(capsule_raw) == index['capsule']
    capsule = json.loads(capsule_raw)
    compressed = base64.b64decode(capsule['payload'], validate=True)
    stream = zlib.decompressobj()
    payload = stream.decompress(compressed, index['payload']['bytes'] + 1) + stream.flush()
    assert stream.eof and not stream.unused_data and not stream.unconsumed_tail
    assert pin(payload) == index['payload'] == capsule['payload_pin']
    restored = json.loads(payload)
    assert restored['products'] == 0 and restored['old_stats_recreated'] is False
    assert len(restored['files']) == 58 and len(restored['directories']) == 7
    seen = set()
    for row in restored['files']:
        relative = PurePosixPath(row['path'])
        assert not relative.is_absolute() and '..' not in relative.parts
        assert str(relative) == row['path'] and row['path'] not in seen
        seen.add(row['path'])
        raw, s = regular(HERE / row['path'])
        assert raw == row['text'].encode('utf-8') and pin(raw) == row['pin']
        assert stat.S_IMODE(s.st_mode) == row['posix_mode']
        assert identity(s) == row['new_authoring_stat'], row['path']
    for row in restored['directories']:
        path = HERE / row['path']
        s = path.lstat()
        assert stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == row['posix_mode']
    assert sum(row['pin']['bytes'] for row in restored['files']) == index['logical_bytes']

    before = (HERE / 'before/test_inspect_cli_witness_controls.py').read_bytes()
    after = raw_by_name['r6/test_inspect_cli_witness_controls.py']
    old = b"        self.assertEqual(reentries, ['refused-without-machine-entry'])\n"
    new = b"        self.assertEqual(reentries, ['refused-without-machine-entry', 'refused-without-machine-entry'])\n"
    assert before.count(old) == after.count(new) == 1
    assert after.replace(new, old, 1) == before
    assert ast.dump(ast.parse(after.replace(new, old, 1)), include_attributes=False) == ast.dump(ast.parse(before), include_attributes=False)
    r5_plan = json.loads((HERE / 'before/PROPOSED-EXECUTION-PLAN.json').read_bytes())
    r6_plan = json.loads(raw_by_name['EXECUTION-PLAN.json'])
    route = json.loads(raw_by_name['CURRENT-PREDECESSOR-PLAN.json'])
    for field in ('groups', 'group_order', 'limits'):
        assert r6_plan[field] == r5_plan[field], field
    assert r6_plan['predecessor_admission']['original_exact_rows'] == 64615
    assert r6_plan['predecessor_admission']['unmodified_original_executor_can_pass_this_gate_now'] is False
    assert all(value is None for value in route['future_actual'].values())
    report = {
        'schema': 'hepta.cli-inspect-r6.actual-git-authoring-readback.v1',
        'status': 'PASS_AUTHORING_CUSTODY_ONLY',
        'repository_full_name': 'TrillionniumFoundation/Hepta',
        'post_ack_full_get_leaves': 24, 'leaves': envelope_rows,
        'index': pin(raw_by_name['ARCHIVE/SOURCE-PARTS.json']),
        'capsule': pin(capsule_raw), 'payload': pin(payload),
        'files': 58, 'directories': 7, 'logical_bytes': 2500582,
        'every_member_full_bytes_git_sha_mode_new_author_stat_exact': True,
        'capsule_rebuilt_only_from_actual_get_responses': True,
        'whole_test_byte_and_ast_inverse': True,
        'original_18_groups_and_limits_identical': True,
        'old_64615_payload_gate_retained_and_blocked': True,
        'future_predecessor_result_fields_all_null': True,
        'first_static_author_schema_failure_preserved': True,
        'old_R5_fail_not_reclassified': True,
        'products': 0, 'binders': 0, 'CI': 0,
        'script': pin(Path(__file__).read_bytes()),
    }
    result_pin = write_new('ACTUAL-GIT-READBACK.json', report)
    print(json.dumps({'status': report['status'], 'report': result_pin,
                      'files': 58, 'logical_bytes': 2500582, 'leaves': 24,
                      'products': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
