"""Independent archive member readback, without reclassifying any run."""
from pathlib import Path
from hashlib import sha256
import json,lzma,tarfile,time
root=Path('/workspace/scratch/9acdfa9f5639');out=root/'recovery-completed-r11'
archive=root/'hia-edit-render-batch-r2-development.tar.xz'
custody=root/'hia-edit-render-batch-r2-development.tar.xz.custody.json'
compressed=root/'hia-edit-render-batch-r2-development.tar.xz.custody.json.xz'
start=time.monotonic_ns();pin=custody.read_bytes();manifest=json.loads(pin)
assert len(pin)==101907604 and sha256(pin).hexdigest()=='09f16d96b2b5247b83b604e17116b7a855f556a0f73cf8f664259b9fc035cf83'
assert lzma.decompress(compressed.read_bytes())==pin
raw=archive.read_bytes();assert len(raw)==41895276 and sha256(raw).hexdigest()=='2b37b276af23a01e9096cfe0bbff24dd786bdae9274261d6b2fe749f97e08be1'
rows={v['path']:v for v in manifest['members']};assert len(rows)==206999
seen=set();total=0
with tarfile.open(archive,'r|xz') as t:
    for m in t:
        assert m.name in rows and m.name not in seen,m.name
        row=rows[m.name];assert m.isfile() and m.mode==row['mode'] and m.size==row['bytes'],m.name
        h=sha256();size=0;f=t.extractfile(m)
        while True:
            block=f.read(1<<20)
            if not block:break
            h.update(block);size+=len(block)
        assert size==row['bytes'] and h.hexdigest()==row['sha256'],m.name
        seen.add(m.name);total+=size
assert len(seen)==len(rows) and total==1321108542
receipt=dict(scope='INDEPENDENT_STORED_MEMBER_READBACK_NOT_NEW_PIPELINE_OR_LOGICAL_CAS_REPLAY',
    archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),custody_bytes=len(pin),custody_sha256=sha256(pin).hexdigest(),
    all_member_bytes_sha256_modes_verified=True,members=len(seen),stored_original_bytes=total,
    peer_recorded_logical_CAS_buffers=manifest['cas_complete_buffer_maps'],peer_recorded_logical_original_bytes=manifest['cas_complete_original_buffer_bytes'],
    compressed_custody_lossless_equal=True,elapsed_ns=time.monotonic_ns()-start)
(out/'batch-root-readback.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
