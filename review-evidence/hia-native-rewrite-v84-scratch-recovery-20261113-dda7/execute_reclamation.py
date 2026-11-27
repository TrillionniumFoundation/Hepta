"""Remove only exact recoverable base files from three inactive scratch exports."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
sys.path.insert(0,str(WORK/'v81-service-requests-development-r1'))
from package_source import manifest, tree_hash


def main():
    plan = json.loads((HERE/'PLAN.json').read_bytes())
    index = json.loads((HERE/'INDEX.json').read_bytes())
    ack = json.loads((HERE/'INDEX-ACK.json').read_bytes())
    assert ack['create_ack'] and ack['full_readback']
    raw_index = (HERE/'INDEX.json').read_bytes()
    assert ack['sha'] == sha1(b'blob '+str(len(raw_index)).encode()+b'\0'+raw_index).hexdigest()
    for row in index['parts']:
        actual = json.loads((HERE/f"ack-{row['number']}.json").read_bytes())
        assert actual == {**row,'create_ack':True,'full_readback':True}
    base = Path(plan['base_source'])
    base_before = manifest(base)
    assert len(base_before) == 3153 and tree_hash(base_before) == plan['base_git_tree']
    targets = [Path(row['source']) for row in plan['targets']]
    busy = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            argv = (proc/'cmdline').read_bytes()
        except (OSError,PermissionError):
            continue
        if any(str(p).encode() in argv for p in targets):
            busy.append(int(proc.name))
    if busy:
        raise RuntimeError('an inactive target appears in a live process: '+repr(busy))
    for row in plan['targets']:
        path = Path(row['source'])
        complete = {**row['recoverable'],**row['retained']}
        actual = manifest(path)
        assert actual == complete and tree_hash(actual) == row['original_tree']
        assert all(base_before[name] == value for name,value in row['recoverable'].items())
    removed = 0
    logical_bytes = 0
    with (HERE/'REMOVED.jsonl').open('x') as receipts:
        for row in plan['targets']:
            root = Path(row['source'])
            for name,expected in sorted(row['recoverable'].items()):
                path = root/name
                raw = path.read_bytes()
                mode = '100755' if path.stat().st_mode&0o111 else '100644'
                actual = {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
                    'blob':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':mode}
                assert actual == expected and raw == (base/name).read_bytes()
                path.unlink()
                receipts.write(json.dumps({'source':str(root),'path':name,'restorable_from_git':plan['base_git_commit'],
                    'bytes':expected['bytes'],'blob':expected['blob']},sort_keys=True)+'\n')
                receipts.flush()
                removed += 1
                logical_bytes += expected['bytes']
            assert manifest(root) == row['retained']
            (root.parent/'PARTIAL-SOURCE-NOT-RUNNABLE.json').write_text(json.dumps({
                'source':str(root),'status':'INACTIVE_PARTIAL_EXACTLY_RECOVERABLE',
                'recovery_index_git_blob':ack['sha'],'original_tree':row['original_tree'],
                'original_file_count':row['original_file_count'],'retained_files':len(row['retained']),
                'production_cleaned':False},sort_keys=True,indent=2)+'\n')
    assert manifest(base) == base_before
    result = {'schema':'hia.exact-inactive-base-reclamation.completed.v84.r1',
        'removed_files':removed,'removed_logical_bytes':logical_bytes,
        'unique_link_bytes_planned':sum(r['single_link_reclaimable_bytes'] for r in plan['targets']),
        'recovery_index_git_blob':ack['sha'],'base_unchanged':True,'retained_deltas_unchanged':True,
        'unique_original_archives_deleted':False,'production_files_deleted':0,'whole_native':False}
    (HERE/'COMPLETE.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    main()
