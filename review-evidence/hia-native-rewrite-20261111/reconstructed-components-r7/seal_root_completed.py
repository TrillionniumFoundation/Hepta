"""Seal completed new merge/apply/batch originals; no running task material."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,stat,tarfile

ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r7'
EDIT=ROOT/'native-agent-edit-development';REPO=ROOT/'Hepta-agent-edit-native';rows={}
def add(path,name):
    assert path.is_file() and not path.is_symlink() and name not in rows
    raw=path.read_bytes();rows[name]=(path,raw,stat.S_IMODE(path.stat().st_mode))
def tree(path,prefix):
    for p in sorted(path.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':add(p,prefix+'/'+p.relative_to(path).as_posix())
for p in sorted(EDIT.iterdir()):
    if p.name.startswith(('graph-merge-','apply-graph-','batch-graph-')):
        if p.is_dir():tree(p,'development/'+p.name)
        else:add(p,'development/'+p.name)
for name in ('graph_merge_harness.py','apply_graph_harness.py','batch_graph_harness.py','packet_graph_harness.py','facts_harness.py',
             'native_query_pipeline.py','freeze_vm_compile_graph_merge_r1.py','test_graph_merge_native_r1.py',
             'freeze_vm_compile_apply_graph_r1.py','test_apply_graph_native_r1.py',
             'freeze_vm_compile_batch_graph_r1.py','test_batch_graph_native_r1.py'):
    add(EDIT/name,'development/'+name)
for name in ('docs/HIA_AGENT_EDIT_APPLY_NATIVE.md','tools/generate_hia_graph_merge.py','tools/generate_hia_agent_edit_apply_graph.py',
             'tools/generate_hia_agent_edit_batch_graph.py','tools/hia_agent_edit_source_views.py',
             'examples/hia_bootstrap/graph_merge.hiaasm','examples/hia_bootstrap/agent_edit_apply_graph.hiaasm',
             'examples/hia_bootstrap/agent_edit_batch_graph.hiaasm'):
    add(REPO/name,'current-source/'+name)
manifest=dict(scope='COMPLETED_NATIVE_GRAPH_MERGE_EDIT_APPLY_BATCH_DEVELOPMENT_NOT_PUBLIC_COORDINATOR',
    original_published_compiler_source='0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    graph_merge_cases=41,graph_merge_private_controls=8,
    apply_cases=122,apply_accepted_exact=106,apply_response_policy_refusals=13,apply_Core_category_refusals=3,apply_private_controls=8,
    batch_end_to_end_groups=7,batch_actual_single_queries=27,batch_private_controls=8,
    original_limits_unchanged=True,whole_stack_closed=False,
    files=[dict(path=name,bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=mode) for name,(path,raw,mode) in sorted(rows.items())])
encoded=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode();archive=OUT/'root-completed-merge-apply-batch.tar.xz'
with tarfile.open(archive,'x:xz') as tf:
    for name,(path,raw,mode) in sorted(rows.items()):
        m=tarfile.TarInfo(name);m.size,m.mode=len(raw),mode;tf.addfile(m,io.BytesIO(raw))
    m=tarfile.TarInfo('MANIFEST.json');m.size,m.mode=len(encoded),0o644;tf.addfile(m,io.BytesIO(encoded))
with tarfile.open(archive,'r:xz') as tf:
    assert len(tf.getmembers())==len(rows)+1 and tf.extractfile('MANIFEST.json').read()==encoded
    for name,(path,raw,mode) in rows.items():
        m=tf.getmember(name);assert m.isfile() and m.mode==mode and tf.extractfile(m).read()==raw
        assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
raw=archive.read_bytes();receipt=dict(scope=manifest['scope'],archive=str(archive),bytes=len(raw),sha256=sha256(raw).hexdigest(),git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),members=len(rows)+1,original_bytes=sum(len(v[1]) for v in rows.values()),all_original_bytes_modes_and_live_readback_equal=True,whole_stack_closed=False)
(OUT/'root-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
