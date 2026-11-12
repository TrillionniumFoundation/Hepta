"""Restore exact existing GitHub objects without network or product execution."""
from pathlib import Path
import datetime, hashlib, json, os, subprocess, zlib

ROOT = Path('/workspace/scratch/e26ed3e2edcf')
REPO = ROOT / 'Hepta'
INPUT = ROOT / 'root/source-import-r1'
META = json.loads((INPUT / 'metadata.json').read_text())
OBJECTS = REPO / '.git/objects'

def digest(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def store(kind, raw, expected=None):
    header = kind.encode() + b' ' + str(len(raw)).encode() + b'\0'
    sha = digest(kind, raw)
    if expected is not None:
        assert sha == expected, (kind, sha, expected)
    path = OBJECTS / sha[:2] / sha[2:]
    path.parent.mkdir(exist_ok=True)
    if path.exists():
        assert zlib.decompress(path.read_bytes()) == header + raw
    else:
        with path.open('xb') as out:
            out.write(zlib.compress(header + raw))
        path.chmod(0o444)
    return sha

blobs = 0
for path in sorted(INPUT.glob('original-blobs-*.json')):
    for row in json.loads(path.read_text())['blobs']:
        raw = row['content'].encode('utf-8')
        assert len(raw) == row['bytes']
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        store('blob', raw, row['sha'])
        blobs += 1

def tree(leaves):
    root = {}
    for leaf in leaves:
        assert leaf['type'] == 'blob'
        parts = leaf['path'].split('/')
        assert all(p not in ('', '.', '..') for p in parts)
        node = root
        for name in parts[:-1]:
            node = node.setdefault(name, {})
        assert parts[-1] not in node
        node[parts[-1]] = leaf
    def write(node):
        entries = []
        for name, item in node.items():
            is_file = isinstance(item, dict) and 'sha' in item
            sha = item['sha'] if is_file else write(item)
            mode = item['mode'] if is_file else '40000'
            order = name.encode() + (b'' if is_file else b'/')
            entries.append((order, mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)))
        return store('tree', b''.join(item for _, item in sorted(entries)))
    return write(root)

def restore_commit(row):
    def person(kind):
        p = row[kind]
        timestamp = int(datetime.datetime.fromisoformat(p['date'].replace('Z', '+00:00')).timestamp())
        return f"{kind} {p['name']} <{p['email']}> {timestamp} +0000"
    lines = ['tree ' + row['tree']['sha']]
    lines += ['parent ' + p['sha'] for p in row['parents']]
    lines += [person('author'), person('committer')]
    prefix = '\n'.join(lines) + '\n\n' + row['message']
    candidates = [prefix.encode(), (prefix + '\n').encode()]
    matching = [raw for raw in candidates if digest('commit', raw) == row['sha']]
    assert len(matching) == 1, ('original commit encoding not recovered', row['sha'])
    store('commit', matching[0], row['sha'])
    return row['sha']

result = []
for name, product in META['products'].items():
    got = tree(product['leaves'])
    assert got == product['commit']['tree']['sha'], (name, got)
    commit = restore_commit(product['commit'])
    result.append({'name': name, 'commit': commit, 'tree': got, 'leaves': len(product['leaves'])})

shallow = REPO / '.git/shallow'
before = shallow.read_text().splitlines()
new = before + [r['commit'] for r in result if r['commit'] not in before]
tmp = REPO / '.git/shallow.hia-import-r1'
with tmp.open('x') as out:
    out.write('\n'.join(new) + '\n')
os.replace(tmp, shallow)
for row in result:
    observed = subprocess.run(['git', 'cat-file', '-t', row['commit']], cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()
    assert observed == 'commit'
    observed = subprocess.run(['git', 'rev-parse', row['commit'] + '^{tree}'], cwd=REPO, check=True, capture_output=True, text=True).stdout.strip()
    assert observed == row['tree']
report = {'schema': 'hia.exact-existing-git-object-import.v1', 'status': 'EXACT_OBJECTS_RESTORED', 'new_original_blobs': blobs, 'products': result, 'base_head_unchanged': subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=REPO, check=True, capture_output=True, text=True).stdout.strip(), 'shallow_boundaries': new, 'ancestor_history_reconstructed': False, 'product_executed': False}
with (INPUT / 'IMPORT-RESULT.json').open('x') as out:
    json.dump(report, out, indent=2); out.write('\n')
print(json.dumps(report, indent=2))
