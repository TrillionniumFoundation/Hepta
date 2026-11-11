"""Complete original edit-composition checkpoint; stream all retained bytes."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,stat,tarfile,time
ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r10';EDIT=ROOT/'native-agent-edit-development';REPO=ROOT/'Hepta-agent-edit-native';rows={}
def digest(path):
    h=sha256();size=0
    with path.open('rb') as f:
        while True:
            block=f.read(1<<20)
            if not block:break
            h.update(block);size+=len(block)
    return size,h.hexdigest()
def add(path,name):
    assert path.is_file() and not path.is_symlink() and name not in rows
    size,hashed=digest(path);rows[name]=dict(source=path,bytes=size,sha256=hashed,mode=stat.S_IMODE(path.stat().st_mode))
def tree(path,prefix):
    for p in sorted(path.rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':add(p,prefix+'/'+p.relative_to(path).as_posix())
for p in sorted(EDIT.iterdir()):
    if p.name.startswith(('complete-edit-','receipt-graph-','envelope-wire-')):
        if p.is_dir():tree(p,'development/'+p.name)
        else:add(p,'development/'+p.name)
for name in ['complete_edit_pipeline.py','receipt_graph_harness.py','envelope_wire_harness.py','run_owned_test.py',
             'freeze_vm_compile_receipt_graph_r1.py','test_receipt_graph_protocol_r1.py',
             'freeze_vm_compile_envelope_wire_r1.py','test_envelope_wire_native_r1.py','test_envelope_wire_native_r2.py',
             'test_complete_edit_pipeline_r1.py','test_complete_edit_pipeline_r2.py','test_complete_edit_pipeline_r3.py',
             'bounded_input_harness.py','input_graph_harness.py','selection_harness.py','native_query_pipeline.py','facts_harness.py',
             'core_packet_transport.py','packet_graph_harness.py','apply_graph_harness.py','graph_merge_harness.py','batch_graph_harness.py','match_wire_harness.py']:
    add(EDIT/name,'development/'+name)
for name in ['docs/HIA_AGENT_EDIT_COMPOSITION_NATIVE.md','tools/hia_agent_edit_source_views.py','tools/generate_hia_agent_edit_apply_graph.py',
             'tools/generate_hia_agent_edit_bounded_input.py','tools/generate_hia_graph_merge.py']:
    add(REPO/name,'current-source/'+name)
for name in ['receipt_graph','envelope_wire']:
    for p in ['tools/generate_hia_agent_edit_'+name+'.py','examples/hia_bootstrap/agent_edit_'+name+'.hiaasm']:add(REPO/p,'current-source/'+p)
for name in ['reclaim_sealed_duplicate_payloads.py','reclaimed-duplicate-payloads.json']:
    add(ROOT/'recovery-completed-r9'/name,'original-reclamation/'+name)
manifest=dict(scope='COMPLETED_NATIVE_EDIT_COMPOSITION_AND_PRIVATE_RECEIPT_FRAMING_NOT_PUBLIC_COORDINATOR',
    original_compiler_source='0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5',
    complete_chain=dict(cases=24,full_candidates_and_complete_receipts=16,exact_public_refusals=6,core_category_refusals_dynamic_text_open=2,wait4_exit=0),
    receipt=dict(independent_VM_cases=4,private_controls=26,actual_protocol_entries=52),
    envelope=dict(independent_VM_cases=4,actual_cases=14,private_controls=36,actual_entries=119,max_complete_frame=16777219),
    original_integration_failure_and_ENOSPC_failure_retained=True,original_expired_wait_observation_retained=True,
    original_limits_unchanged=True,whole_stack_closed=False,
    files=[dict(path=name,**{k:v for k,v in row.items() if k!='source'}) for name,row in sorted(rows.items())])
encoded=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode();archive=OUT/'root-completed-edit-composition.tar.xz';started=time.monotonic_ns()
with tarfile.open(archive,'x:xz',preset=1) as tf:
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
            block=f.read(1<<20)
            if not block:break
            h.update(block);size+=len(block)
        assert (size,h.hexdigest())==(row['bytes'],row['sha256'])
        assert digest(row['source'])==(row['bytes'],row['sha256']) and stat.S_IMODE(row['source'].stat().st_mode)==row['mode']
assert seen==set(rows)|{'MANIFEST.json'}
raw=archive.read_bytes();receipt=dict(scope=manifest['scope'],archive=str(archive),bytes=len(raw),sha256=sha256(raw).hexdigest(),
    git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),members=len(rows)+1,
    original_bytes=sum(r['bytes'] for r in rows.values())+len(encoded),all_original_bytes_modes_and_live_readback_equal=True,
    elapsed_ns=time.monotonic_ns()-started,whole_stack_closed=False)
(OUT/'root-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
