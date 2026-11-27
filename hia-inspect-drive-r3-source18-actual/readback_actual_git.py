"""Restore actual Git parts and compare every archived original, without products."""
from pathlib import Path
import base64, gzip, hashlib, io, json, os, stat, tarfile, time

ROOT = Path('/tmp/hia-inspect-drive-r3-source18-custody-dda7')
ACK = ROOT / 'GIT-ACK'

def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def seven(s):
    return {'device': s.st_dev, 'inode': s.st_ino, 'nlink': s.st_nlink, 'mode': s.st_mode,
            'bytes': s.st_size, 'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}

def same_original(row, raw):
    path = Path(row['source'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        assert stat.S_ISREG(os.fstat(fd).st_mode)
        assert seven(os.fstat(fd)) == row['stat'] == seven(path.lstat())
        offset = 0
        while offset < len(raw):
            block = os.read(fd, min(1048576, len(raw) - offset))
            assert block and block == raw[offset:offset + len(block)]
            offset += len(block)
        assert os.read(fd, 1) == b''
        assert seven(os.fstat(fd)) == row['stat'] == seven(path.lstat())
    finally:
        os.close(fd)

def write_new(name, raw):
    fd = os.open(ROOT / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def main():
    started = time.monotonic_ns()
    rows = json.loads((ROOT / 'PUBLICATION-INPUTS.json').read_bytes())
    by_name = {row['file']: row for row in rows}
    assert len(by_name) == len(rows) == 11
    receipts = []
    def actual_get(name):
        expected = by_name[name]['pin']
        post_raw = (ACK / (name + '.POST.json')).read_bytes()
        get_raw = (ACK / (name + '.GET.json')).read_bytes()
        post, get = json.loads(post_raw), json.loads(get_raw)
        assert not post.get('isError') and not get.get('isError')
        assert post['structuredContent']['sha'] == expected['git_blob']
        raw = get['structuredContent']['content'].encode('utf-8')
        assert pin(raw) == expected and raw == (ROOT / name).read_bytes()
        receipts.append({'file': name, 'pin': expected, 'post': pin(post_raw), 'get': pin(get_raw)})
        return raw
    index_raw = actual_get('PARTS-INDEX.json')
    assert pin(index_raw)['git_blob'] == 'a2260e8ac824d9165f15c374b3c81b48189fe7fa'
    index = json.loads(index_raw)
    assert index['complete'] is True and len(index['parts']) == 7
    pieces, offset = [], 0
    for number, row in enumerate(index['parts']):
        assert row['index'] == number and row['pin'] == by_name[row['file']]['pin']
        part = json.loads(actual_get(row['file']))
        assert part['schema'] == 'hepta.hia.lossless-archive-part.v1'
        assert part['index'] == number and part['decoded_offset'] == offset
        assert part['archive_sha256'] == index['archive']['sha256']
        piece = base64.b64decode(part['base64'], validate=True)
        assert len(piece) == part['decoded_bytes'] == row['decoded_bytes']
        assert hashlib.sha256(piece).hexdigest() == part['decoded_sha256'] == row['decoded_sha256']
        pieces.append(piece); offset += len(piece)
    archive = b''.join(pieces)
    assert pin(archive) == index['archive']
    assert archive == (ROOT / 'COMPLETE-ACTUAL.tar.gz').read_bytes()
    manifest_raw = actual_get('MANIFEST.json')
    local = json.loads(actual_get('READBACK.json'))
    actual = json.loads(actual_get('ACTUAL-READBACK.json'))
    assert local['status'] == actual['status'] == 'PASS'
    assert local['archive'] == index['archive'] and local['manifest'] == pin(manifest_raw)
    assert actual['result']['git_blob'] == '66a7fcb126e87224d171b6869be08e28e2d1cec6'
    assert (actual['methods'], actual['events'], actual['subtests']) == (18, 36, 21)
    manifest = json.loads(manifest_raw)
    by_key = {}
    for row in manifest['nodes']:
        if row['type'] == 'file': by_key.setdefault(row['pin']['sha256'], []).append(row)
    assert len(manifest['nodes']) == 75 and len(by_key) == 51
    seen, manifests = set(), 0
    with gzip.GzipFile(fileobj=io.BytesIO(archive), mode='rb') as gz:
        with tarfile.open(fileobj=gz, mode='r|') as tar:
            for member in tar:
                assert member.isfile() and member.mode == 0o644
                assert member.uid == member.gid == member.mtime == 0
                raw = tar.extractfile(member).read()
                if member.name == 'MANIFEST.json':
                    assert manifests == 0 and raw == manifest_raw
                    manifests += 1; continue
                assert member.name.startswith('CAS/')
                key = member.name[4:]
                assert key in by_key and key not in seen
                identity = pin(raw)
                for row in by_key[key]:
                    assert identity == row['pin']; same_original(row, raw)
                seen.add(key)
        while gz.read(1048576): pass
    assert manifests == 1 and seen == set(by_key)
    expected_children = {}
    for row in manifest['nodes']:
        path = Path(row['source']); now = path.lstat()
        assert seven(now) == row['stat'] and stat.S_IMODE(now.st_mode) == row['posix_mode']
        if row['type'] == 'directory':
            assert stat.S_ISDIR(now.st_mode); expected_children[str(path)] = set()
        elif row['type'] == 'symlink':
            assert stat.S_ISLNK(now.st_mode) and os.readlink(path) == row['target']
        else: assert row['type'] == 'file' and stat.S_ISREG(now.st_mode)
    for row in manifest['nodes']:
        path = Path(row['source'])
        if str(path.parent) in expected_children: expected_children[str(path.parent)].add(path.name)
    for name, children in expected_children.items():
        assert {path.name for path in Path(name).iterdir()} == children
    assert manifest['files'] == 65 and manifest['directories'] == 10 and manifest['symlinks'] == 0
    assert manifest['logical_bytes'] == 14733363
    report = {'schema': 'hepta.hia.inspect-source18-actual-Git-full-restore.v1',
        'status': 'PASS_ACTUAL_GIT_COMPLETE_RESTORE', 'manifest': pin(manifest_raw),
        'archive': pin(archive), 'parts_index': pin(index_raw), 'receipts': receipts,
        'parts': 7, 'files': 65, 'directories': 10, 'symlinks': 0, 'logical_bytes': 14733363,
        'unique_blobs': 51, 'unique_bytes': manifest['unique_bytes'],
        'raw_evidence_files': 55, 'raw_evidence_logical_bytes': 14606934,
        'all_actual_POST_GET_tool_envelopes_checked': True, 'full_archive_SHA_Git_CRC_checked': True,
        'all_logical_current_bytes_modes_seven_stats_pathsets_equal': True,
        'physical_expanded_duplicate_created': False, 'product_executions': 0,
        'qualification': 'actual Source18 only; Native and VM are separate',
        'elapsed_ns': time.monotonic_ns() - started}
    write_new('ACTUAL-GIT-READBACK.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    print(json.dumps({k: v for k, v in report.items() if k != 'receipts'}, sort_keys=True))

if __name__ == '__main__': main()
