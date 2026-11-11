"""Stream completed originals without rewriting failed runs or mutable work."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,stat,tarfile,time
ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r9'
EDIT=ROOT/'native-agent-edit-development';REPO=ROOT/'Hepta-agent-edit-native';rows={}
def digest(path):
    h=sha256();size=0
    with path.open('rb') as f:
        while True:
            chunk=f.read(1<<20)
            if not chunk:break
            h.update(chunk);size+=len(chunk)
    return size,h.hexdigest()
def add(path,name):
    assert path.is_file() and not path.is_symlink() and name not in rows
    size,hashed=digest(path);rows[name]=dict(source=path,bytes=size,sha256=hashed,mode=stat.S_IMODE(path.stat().st_mode))
def tree(path,prefix):
    for p in sorted(path.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':add(p,prefix+'/'+p.relative_to(path).as_posix())
for p in sorted(EDIT.iterdir()):
    selected=p.name.startswith(('input-graph-','bounded-input-','match-wire-','selection-generation-r3','selection-source-and-compile-r3','selection-native-r4'))
    if selected:
        if p.is_dir():tree(p,'development/'+p.name)
        else:add(p,'development/'+p.name)
names=['selection_harness.py','input_graph_harness.py','bounded_input_harness.py','match_wire_harness.py',
       'core_packet_transport.py','native_query_pipeline.py','packet_graph_harness.py','facts_harness.py',
       'graph_merge_harness.py','batch_graph_harness.py','apply_graph_harness.py',
       'freeze_vm_compile_selection_r3.py','test_selection_native_r4.py',
       'freeze_vm_compile_input_graph_r1.py','test_input_graph_native_r1.py','test_input_graph_native_r2.py',
       'freeze_vm_compile_bounded_input_r2.py','freeze_vm_compile_bounded_input_r3.py',
       'test_bounded_input_native_r2.py','test_bounded_input_native_r3.py','replay_recorded_bounded_r2_counterexample.py',
       'freeze_vm_compile_match_wire_r1.py','test_match_wire_native_r1.py']
for name in names:add(EDIT/name,'development/'+name)
for name in ['docs/HIA_AGENT_EDIT_SELECTION_NATIVE.md','docs/HIA_AGENT_EDIT_INPUT_PREFIX_NATIVE.md','docs/HIA_AGENT_EDIT_BOUNDED_INPUT_ABI.md',
             'tools/hia_agent_edit_source_views.py','tools/generate_hia_agent_edit_apply_graph.py','tools/generate_hia_graph_merge.py',
             'tools/generate_hia_agent_edit_query_packet.py']:
    add(REPO/name,'current-source/'+name)
for component in ['selection','input_graph','bounded_input','match_wire']:
    for name in ['tools/generate_hia_agent_edit_'+component+'.py','examples/hia_bootstrap/agent_edit_'+component+'.hiaasm']:
        add(REPO/name,'current-source/'+name)
manifest=dict(scope='COMPLETED_NATIVE_EDIT_PREFIX_INPUT_MATCH_DEVELOPMENT_NOT_PUBLIC_COORDINATOR',
    original_published_compiler_source='0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    selection=dict(public_cases=122,private_controls=11,actual_entries=182,complete_native_queries=38),
    input_prefix=dict(prefix_cases=85,whole_query_chains=12,private_controls=8,complete_native_queries=31),
    bounded_input=dict(public_cases=196,private_controls=63,actual_outer_entries=985),
    match_wire=dict(comparisons=56,private_controls=21,actual_entries=92),
    all_original_failures_and_r2_private_counterexample_retained=True,original_limits_unchanged=True,whole_stack_closed=False,
    files=[dict(path=name,**{k:v for k,v in row.items() if k!='source'}) for name,row in sorted(rows.items())])
encoded=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode();archive=OUT/'root-completed-edit-inputs.tar.xz'
started=time.monotonic_ns()
with tarfile.open(archive,'x:xz') as tf:
    for name,row in sorted(rows.items()):
        m=tarfile.TarInfo(name);m.size,m.mode=row['bytes'],row['mode']
        with row['source'].open('rb') as f:tf.addfile(m,f)
    m=tarfile.TarInfo('MANIFEST.json');m.size,m.mode=len(encoded),0o644;tf.addfile(m,io.BytesIO(encoded))
seen=set()
with tarfile.open(archive,'r|xz') as tf:
    for m in tf:
        assert m.isfile() and m.name not in seen;seen.add(m.name);f=tf.extractfile(m)
        if m.name=='MANIFEST.json':assert m.mode==0o644 and f.read()==encoded;continue
        row=rows[m.name];assert (m.size,m.mode)==(row['bytes'],row['mode']);h=sha256();size=0
        while True:
            chunk=f.read(1<<20)
            if not chunk:break
            h.update(chunk);size+=len(chunk)
        assert (size,h.hexdigest())==(row['bytes'],row['sha256'])
        assert digest(row['source'])==(row['bytes'],row['sha256']) and stat.S_IMODE(row['source'].stat().st_mode)==row['mode']
assert seen==set(rows)|{'MANIFEST.json'}
raw=archive.read_bytes();receipt=dict(scope=manifest['scope'],archive=str(archive),bytes=len(raw),sha256=sha256(raw).hexdigest(),
    git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),members=len(rows)+1,
    original_bytes=sum(row['bytes'] for row in rows.values())+len(encoded),all_original_bytes_modes_and_live_readback_equal=True,
    whole_stack_closed=False,elapsed_ns=time.monotonic_ns()-started)
(OUT/'root-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
