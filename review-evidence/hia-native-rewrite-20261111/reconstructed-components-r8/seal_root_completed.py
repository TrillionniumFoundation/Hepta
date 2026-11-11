"""Seal completed selection/actual Core codec/query originals, all failures kept."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,stat,tarfile
ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r8'
EDIT=ROOT/'native-agent-edit-development';REPO=ROOT/'Hepta-agent-edit-native';rows={}
def add(path,name):
    assert path.is_file() and not path.is_symlink() and name not in rows
    raw=path.read_bytes();rows[name]=(path,raw,stat.S_IMODE(path.stat().st_mode))
def tree(path,prefix):
    for p in sorted(path.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':add(p,prefix+'/'+p.relative_to(path).as_posix())
for p in sorted(EDIT.iterdir()):
    if p.name.startswith('selection-'):
        if p.is_dir():tree(p,'development/'+p.name)
        else:add(p,'development/'+p.name)
for name in ('selection_harness.py','core_packet_transport.py','packet_graph_harness.py','facts_harness.py','native_query_pipeline.py',
             'freeze_vm_compile_selection_r2.py','test_selection_native_r2.py','test_selection_native_r3.py'):
    add(EDIT/name,'development/'+name)
for name in ('docs/HIA_AGENT_EDIT_SELECTION_NATIVE.md','tools/generate_hia_agent_edit_selection.py','tools/hia_agent_edit_source_views.py',
             'examples/hia_bootstrap/agent_edit_selection.hiaasm'):
    add(REPO/name,'current-source/'+name)
manifest=dict(scope='COMPLETED_NATIVE_SELECTION_CORE_CODEC_QUERY_DEVELOPMENT_NOT_PUBLIC_COORDINATOR',
    original_published_compiler_source='0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    independent_VM_cases=7,independent_VM_entries=9,actual_cases=121,private_controls=11,
    actual_selector_entries=181,actual_complete_native_queries=38,actual_admitted_core_inputs=6,
    original_authoring_r1_failure_retained=True,original_native_r2_harness_failure_retained=True,
    original_limits_unchanged=True,whole_stack_closed=False,
    files=[dict(path=name,bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=mode) for name,(path,raw,mode) in sorted(rows.items())])
encoded=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode();archive=OUT/'root-completed-selection.tar.xz'
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
