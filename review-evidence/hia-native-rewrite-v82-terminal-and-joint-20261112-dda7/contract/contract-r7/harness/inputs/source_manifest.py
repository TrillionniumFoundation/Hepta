"""Restore the exact observed pre-Proof R2 source to a fresh plain export."""
from pathlib import Path
from hashlib import sha1, sha256
import base64
import json
import os
import shutil

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent
PACKET = WORKSPACE / 'v79-joint-full-harness-authoring-r1/preproof-r2-original/SOURCE-PACKET.json'
BASE = WORKSPACE / 'v76-product-publication-r1/source'


def identify(data):
    return {'bytes': len(data), 'sha256': sha256(data).hexdigest(),
            'blob': sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def manifest(root):
    result = {}
    for directory, directories, names in os.walk(root):
        directories[:] = sorted(d for d in directories if d != '__pycache__')
        if '.git' in directories:
            raise ValueError('unexpected Git directory in plain export')
        for name in names:
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError('source symlink: ' + str(path))
            data = path.read_bytes()
            result[path.relative_to(root).as_posix()] = {
                **identify(data), 'mode': '100755' if path.stat().st_mode & 0o111 else '100644'}
    return result


def simple(expected):
    return {p: {k: row[k] for k in ('bytes', 'sha256', 'blob', 'mode')}
            for p, row in expected.items()}


def tree_hash(files):
    root = {}
    for path, row in files.items():
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = (row['mode'], row['blob'])
    def visit(node):
        raw = bytearray()
        for name, value in sorted(node.items(), key=lambda pair: (pair[0] + ('/' if isinstance(pair[1], dict) else '')).encode()):
            mode, digest = ('40000', visit(value)) if isinstance(value, dict) else value
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
        return sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return visit(root)


def main():
    raw = PACKET.read_bytes()
    if len(raw) != 9521085 or sha256(raw).hexdigest() != '0fdf556bc32a78f255fae388b6091d3e781c1ed3c384b0a04ec77db00e85f46d':
        raise ValueError('exact actual source packet differs')
    packet = json.loads(raw)
    if manifest(BASE) != simple(packet['base_files']):
        raise ValueError('local 4b source is not the exact 3153-file base')
    original = ROOT / 'original-source'
    shutil.copytree(BASE, original, ignore=shutil.ignore_patterns('__pycache__'))
    for item in packet['files']:
        path = original / item['path']
        if item['status'] == 'deleted':
            path.unlink()
            continue
        raw = item['content'].encode('utf-8') if item['encoding'] == 'utf-8' else base64.b64decode(item['content'], validate=True)
        if identify(raw) != {key: item[key] for key in ('bytes', 'sha256', 'blob')}:
            raise ValueError('delta identity differs: ' + item['path'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(int(item['mode'], 8) & 0o777)
    observed = manifest(original)
    if observed != simple(packet['final_files']):
        raise ValueError('complete reconstructed 3239-source snapshot differs')
    tree = tree_hash(observed)
    if tree != packet['actual_write_tree'] or tree != 'aa32ea9110b9b50e5840392324b7ffbcf86d0f45':
        raise ValueError('actual original generated Git tree differs')
    working = ROOT / 'source'
    shutil.copytree(original, working)
    if manifest(working) != observed:
        raise ValueError('new development copy differs')
    report = {'schema': 'hia.global-semantics.exact-source-restoration.v80.r1',
              'base_commit': packet['base_commit'], 'base_files': len(packet['base_files']),
              'source_files': len(observed), 'source_tree': tree,
              'original_source_run': 43264682454,
              'original_source_status': '826 tests, one original closure FAIL; not qualified',
              'new_tests_executed': False, 'whole_native': False,
              'packet': identify(PACKET.read_bytes()), 'manifest': observed}
    (ROOT / 'SOURCE-RESTORATION.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('manifest', 'packet')}, sort_keys=True))


if __name__ == '__main__':
    main()
