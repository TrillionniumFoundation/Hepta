"""Independently stream the exact restorer and compare four extant originals."""
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save, identity
import review_v92_failed_ci_recovery_r1 as git

OUT = Path('/workspace/scratch/e26ed3e2edcf/root/small-derived-cache-compaction-r1')


def main():
    assert pin(OUT / 'CANDIDATES-READBACK.json')['sha256'] == '9d4a5ab0c6e55c6715affc023094dee91a01265d4c143af8b6e5594a67325aaa'
    assert pin(OUT / 'V83-RESTORE-RECIPE.json')['sha256'] == '83282040d026632e4eb0151166fa4c7c92e7222cd5d51c8b20e7dc8e5cf48a08'
    spec = importlib.util.spec_from_file_location('root_four_exact_transport_restore', OUT / 'restore_derived.py')
    restore = importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)
    proof, recipe, targets = restore.records()
    assert len(targets) == 4 and proof['active_reference_search']['returncode'] == 1
    assert proof['active_reference_search']['matched_files'] == [] and proof['active_reference_search']['stderr'] == ''
    tree = js(OUT.parent / 'v89-derived-part-compaction-r1/publication/TREE.provider.json')
    leaves = {r['path']: r for r in tree['tree'] if r['type'] != 'tree'}
    assert len(leaves) == 5827 and git.tree_hash(leaves) == tree['sha'] == recipe['source_tree']
    for row in recipe['retained_files_in_exact_bundle_order']:
        p = Path(row['path']); raw = read(p)
        assert identity(p.lstat()) == row['identity']
        assert all(pin(p)[k] == row[k] for k in ('bytes', 'sha256', 'git_blob'))
        assert leaves[row['canonical_path']]['sha'] == row['git_blob']
    observations = []
    for index, target in enumerate(targets):
        p = Path(target['path'])
        assert identity(p.lstat()) == target['identity']
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            assert identity(os.fstat(fd)) == target['identity']
            size = 0; sha = hashlib.sha256()
            for part in restore.pieces(index):
                assert os.pread(fd, len(part), size) == part
                size += len(part); sha.update(part)
            assert size == target['bytes'] and sha.hexdigest() == target['sha256']
            assert identity(os.fstat(fd)) == target['identity'] == identity(p.lstat())
            observations.append({'index': index, 'target': target, 'every_byte_compared_using_actual_restorer': True})
        finally:
            os.close(fd)
    current_inputs = [OUT.parent.parent / n for n in [
        'v92-three-part-view-plan-r1-20261113-e26e/POLICY.json',
        'full32-stream-private-proxy-plan-r3-20261113-e26e/POLICY.json',
        'native-cli-c-runtime-lifetime-plan-r4b/POLICY.json']]
    for p in current_inputs:
        raw = read(p)
        assert all(t['path'].encode() not in raw for t in targets)
    result = {'schema': 'hia.root.four-derived-transport-inverse-review.v1',
        'status': 'ALL_FOUR_EXACT_RESTORER_STREAMS_EQUAL_ORIGINALS',
        'restorer': pin(OUT / 'restore_derived.py'), 'peer_proof': pin(OUT / 'CANDIDATES-READBACK.json'),
        'recipe': pin(OUT / 'V83-RESTORE-RECIPE.json'), 'observations': observations,
        'all39_v83_retained_local_bodies_join_recomputed_latest_tree': True,
        'fresh39_remote_body_GET_claimed': False, 'four_bytes': sum(t['bytes'] for t in targets),
        'all_retained_parts_and_metadata_still_required': True,
        'current_exact_policies_checked': [pin(p) for p in current_inputs],
        'active_reference_search_limitations_preserved': proof['active_reference_search'],
        'global_cross_namespace_open_reader_absence_claimed': False,
        'unlink_performed': False, 'product_or_qualification_execution': False}
    save(OUT / 'ROOT-INVERSE-READBACK.json', result)
    print(json.dumps({'status': result['status'], 'readback': pin(OUT / 'ROOT-INVERSE-READBACK.json'), 'four_bytes': result['four_bytes']}))


if __name__ == '__main__':
    main()
