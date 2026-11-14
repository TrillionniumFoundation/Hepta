"""Read the complete saved Git tool responses and unchanged author files."""
from pathlib import Path
import hashlib
import json
import stat

ROOT = Path('/workspace/hia-cli-as-dict-owner-publication-r1-dda7')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def tool_object(value):
    assert not value.get('isError')
    current = value.get('structuredContent')
    if isinstance(current, dict):
        if isinstance(current.get('content'), str):
            try:
                return json.loads(current['content'])
            except json.JSONDecodeError:
                pass
        return current
    for item in value.get('content', []):
        if item.get('type') == 'text':
            try:
                return json.loads(item['text'])
            except json.JSONDecodeError:
                pass
    raise AssertionError('complete tool response has no result object')


def main():
    plan = json.loads((ROOT / 'PUBLICATION-PLAN.json').read_bytes())
    source = Path(plan['source_root'])
    actual_paths = []
    for path in sorted(source.rglob('*')):
        observed = path.lstat()
        assert not stat.S_ISLNK(observed.st_mode)
        if stat.S_ISDIR(observed.st_mode):
            continue
        assert stat.S_ISREG(observed.st_mode)
        actual_paths.append(path.relative_to(source).as_posix())
    assert actual_paths == [row['path'] for row in plan['files']]
    rows = []
    for index, expected in enumerate(plan['files']):
        name = '%03d.json' % index
        path = source / expected['path']
        before = path.lstat()
        raw = path.read_bytes()
        after = path.lstat()
        assert {key: getattr(before, key) for key in FIELDS} == expected['stat']
        assert all(getattr(before, key) == getattr(after, key) for key in FIELDS)
        assert stat.S_IMODE(before.st_mode) == expected['posix_mode'] == 0o644
        assert pin(raw) == {key: expected[key] for key in ('bytes', 'sha256', 'git_blob')}
        intent_raw = (ROOT / 'INTENTS' / name).read_bytes()
        ack_raw = (ROOT / 'ACK' / name).read_bytes()
        get_raw = (ROOT / 'GET' / name).read_bytes()
        verified_raw = (ROOT / 'VERIFIED' / name).read_bytes()
        intent, ack, got, verified = map(json.loads, (intent_raw, ack_raw, get_raw, verified_raw))
        assert intent['sha'] == expected['git_blob'] and intent['path'] == expected['path']
        assert tool_object(ack)['sha'] == expected['git_blob']
        assert not got.get('isError')
        fetched = got['structuredContent']['content'].encode('utf-8')
        assert fetched == raw
        assert pin(fetched) == pin(raw)
        assert verified['full_get_exact'] is True
        assert verified['full_get_bytes'] == len(raw)
        assert verified['full_get_git_blob'] == expected['git_blob']
        assert verified['full_get_sha256'] == expected['sha256']
        rows.append({**expected, 'post_ack_sha': tool_object(ack)['sha'],
                     'full_get_exact': True, 'full_get_pin': pin(fetched),
                     'author_stat_before_after_exact': True,
                     'local_transport_records': {
                         kind: {'path': str(ROOT / kind / name), **pin(payload)}
                         for kind, payload in (('INTENTS', intent_raw), ('ACK', ack_raw),
                                               ('GET', get_raw), ('VERIFIED', verified_raw))}})
    assert len(rows) == 18 and sum(row['bytes'] for row in rows) == 155090
    result = {'schema': 'hia.cli-as-dict.author-publication-readback.v1',
              'status': 'PASS_IMMUTABLE_AUTHOR_BYTES_POST_AND_FULL_GET_ONLY',
              'repository': plan['repository'], 'source_root': str(source),
              'files': rows, 'count': len(rows), 'logical_bytes': 155090,
              'source_pathset_exact': True, 'all_current_seven_stats_exact': True,
              'all_local_bytes_equal_complete_git_get': True,
              'product_execution': 0, 'project_imports': 0, 'refs_written': 0,
              'author_files_mutated': False, 'historical_author_only_documents_unchanged': True,
              'raw_api_tool_responses': 'Complete saved local responses are identified per file; no HTTP credentials or signed download URLs were used.'}
    output = ROOT / 'PUBLICATION-RESULT.json'
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    output.chmod(0o644)
    print(json.dumps({'status': result['status'], 'count': len(rows),
                      'logical_bytes': 155090, 'result': str(output), **pin(output.read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    main()
