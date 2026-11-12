"""Local journal and independent immutable Git-object arithmetic; no network."""
from pathlib import Path
from hashlib import sha256, sha1
import json
import os
import sys

ROOT = Path(__file__).resolve().parent


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def tree_hash(leaves):
    root = {}
    for row in leaves:
        at = root
        components = row['path'].split('/')
        for component in components[:-1]:
            at = at.setdefault(component, {})
        assert components[-1] not in at
        at[components[-1]] = (row['mode'], row['sha'])
    objects = {}
    def make(node, path):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                digest = make(value, path + '/' + name if path else name)
                entries.append((name + '/', '40000', name, digest))
            else:
                entries.append((name, value[0], name, value[1]))
        raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
            for _, mode, name, digest in sorted(entries, key=lambda x: x[0].encode()))
        digest = sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        objects[path] = digest
        return digest
    return make(root, ''), objects


def main():
    operation = sys.argv[1]
    if operation == 'read':
        path, start, count = Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        raw = path.read_bytes(); text = raw.decode()
        print(json.dumps({'text': text[start:start + count], 'chars': len(text), **pin(raw)}))
    elif operation in ('write', 'append'):
        path, raw = Path(sys.argv[2]), sys.argv[3].encode()
        with path.open('xb' if operation == 'write' else 'ab') as out:
            out.write(raw); out.flush(); os.fsync(out.fileno())
        print(json.dumps({'written': len(raw)}))
    elif operation == 'journal':
        row = json.loads(sys.argv[2])
        with (ROOT / 'publish/JOURNAL.jsonl').open('ab') as out:
            raw = (json.dumps(row, sort_keys=True) + '\n').encode()
            out.write(raw); out.flush(); os.fsync(out.fileno())
        print(json.dumps({'journaled': True}))
    elif operation == 'plan':
        published = json.loads((ROOT / 'PUBLICATION-FILES.json').read_bytes())
        records = published['files']
        raw = (ROOT / 'PUBLICATION-FILES.json').read_bytes()
        records.append({'local': str(ROOT / 'PUBLICATION-FILES.json'), 'relative': 'PUBLICATION-FILES.json',
            'path': published['prefix'] + '/FILES.json', 'mode': '100644', **pin(raw)})
        plan = {'files': records, 'bytes': sum(x['bytes'] for x in records),
            'base_commit': 'e4fc00a775dab323758d77a2ef4918fd35585cdc',
            'base_tree': 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790', 'prefix': published['prefix']}
        with (ROOT / 'publish/PLAN.json').open('x') as out: json.dump(plan, out, sort_keys=True, indent=2)
        print(json.dumps(plan))
    elif operation == 'tree-plan':
        raw_tree = json.loads((ROOT / 'publish/BASE-TREE.original.json').read_bytes())
        plan = json.loads((ROOT / 'publish/PLAN.json').read_bytes())
        original = [x for x in raw_tree['tree'] if x['type'] != 'tree']
        assert len(original) == 4076 and tree_hash(original)[0] == plan['base_tree'] == raw_tree['sha']
        assert not raw_tree['truncated']
        leaves = [{key: row[key] for key in ('path', 'mode', 'type', 'sha')} for row in original]
        keys = {x['path'] for x in leaves}
        elements = []
        for row in plan['files']:
            assert row['path'] not in keys
            elements.append({'path': row['path'], 'mode': row['mode'], 'type': 'blob', 'sha': row['git_blob']})
        leaves.extend(elements)
        digest, objects = tree_hash(leaves)
        result = {'expected_sha': digest, 'base_tree': plan['base_tree'], 'base_leaves': 4076,
            'new_leaves': len(elements), 'total_leaves': len(leaves), 'elements': elements,
            'all_leaves': sorted(leaves, key=lambda x: x['path']), 'subtree_hashes': objects}
        with (ROOT / 'publish/A-TREE-PLAN.json').open('x') as out: json.dump(result, out, sort_keys=True, indent=2)
        print(json.dumps({key: result[key] for key in ('expected_sha', 'base_tree', 'base_leaves', 'new_leaves', 'total_leaves', 'elements')}))
    elif operation == 'verify-tree':
        got = json.loads(Path(sys.argv[2]).read_bytes())
        plan = json.loads(Path(sys.argv[3]).read_bytes())
        leaves = [{key: row[key] for key in ('path', 'mode', 'type', 'sha')} for row in got['tree'] if row['type'] != 'tree']
        assert not got['truncated'] and got['sha'] == plan['expected_sha']
        assert tree_hash(leaves)[0] == got['sha']
        assert sorted(leaves, key=lambda x: x['path']) == plan['all_leaves']
        print(json.dumps({'status': 'COMPLETE_TREE_EXACT', 'sha': got['sha'], 'leaves': len(leaves)}))
    else:
        raise ValueError(operation)


if __name__ == '__main__':
    main()
