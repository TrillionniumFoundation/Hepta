from pathlib import Path

from hashlib import sha256, sha1

import json

import os

import sys

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

ROOT = Path(__file__).resolve().parent

def main():
    op=sys.argv[1]
    if op == 'read':
        p=Path(sys.argv[2]); raw=p.read_bytes(); s=raw.decode()
        start,count=int(sys.argv[3]),int(sys.argv[4])
        print(json.dumps({'text':s[start:start+count],'chars':len(s),**pin(raw)}))
    elif op in ('write','append'):
        p=Path(sys.argv[2]); raw=sys.argv[3].encode()
        with p.open('xb' if op=='write' else 'ab') as out:
            out.write(raw);out.flush();os.fsync(out.fileno())
        print(json.dumps({'written':len(raw)}))
    elif op == 'journal':
        value=json.loads(sys.argv[2]);raw=(json.dumps(value,sort_keys=True)+'\n').encode()
        with (ROOT/'publish/JOURNAL.jsonl').open('ab') as out:
            out.write(raw);out.flush();os.fsync(out.fileno())
        print(json.dumps({'journaled':True}))
    elif op == 'tree-plan':
        base=json.loads((ROOT/'publish/BASE-TREE.original.json').read_bytes())
        plan=json.loads((ROOT/'publish/PLAN.json').read_bytes())
        leaves=[{k:x[k] for k in ('path','mode','type','sha')} for x in base['tree'] if x['type']!='tree']
        assert not base['truncated'] and len(leaves)==4136
        assert tree_hash(leaves)[0]==base['sha']==plan['base_tree']
        new=[{'path':x['path'],'mode':x['mode'],'type':'blob','sha':x['git_blob']} for x in plan['files']]
        assert not ({x['path'] for x in leaves}&{x['path'] for x in new})
        leaves+=new; expected,sub=tree_hash(leaves)
        result={'expected_sha':expected,'base_tree':base['sha'],'elements':new,'all_leaves':sorted(leaves,key=lambda x:x['path']),'base_leaves':4136,'new_leaves':len(new),'total_leaves':len(leaves),'subtrees':sub}
        with (ROOT/'publish/TREE-PLAN.json').open('x') as out:json.dump(result,out,sort_keys=True,indent=2)
        print(json.dumps({k:result[k] for k in ('expected_sha','base_tree','base_leaves','new_leaves','total_leaves')}))
    elif op == 'verify-tree':
        actual=json.loads(Path(sys.argv[2]).read_bytes());plan=json.loads(Path(sys.argv[3]).read_bytes())
        leaves=[{k:x[k] for k in ('path','mode','type','sha')} for x in actual['tree'] if x['type']!='tree']
        assert not actual['truncated'] and actual['sha']==plan['expected_sha']==tree_hash(leaves)[0]
        assert sorted(leaves,key=lambda x:x['path'])==plan['all_leaves']
        print(json.dumps({'status':'COMPLETE_TREE_EXACT','sha':actual['sha'],'leaves':len(leaves)}))
    else:raise ValueError(op)
if __name__=='__main__':main()
