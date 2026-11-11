"""Independent streaming readback of each original member, including modes."""
from pathlib import Path
from hashlib import sha256
import json,lzma,tarfile,time
ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r9'
items=[('edit-decode',ROOT/'hia-edit-decode-r2-development.tar.xz',ROOT/'hia-edit-decode-r2-development.tar.xz.custody.json','members'),
       ('legacy-import',ROOT/'hia-legacy-composite-native-import-r3-development.tar.xz',ROOT/'hia-legacy-composite-native-import-r3-development.tar.members.json',None)]
for label,archive,manifest,key in items:
    started=time.monotonic_ns();manifest_raw=manifest.read_bytes();value=json.loads(manifest_raw)
    rows=value[key] if key else value;expected={r['path']:r for r in rows};assert len(expected)==len(rows)
    seen=set();count=0;total=0;directories=0
    with tarfile.open(archive,'r|xz') as tf:
        for member in tf:
            assert member.name not in seen;seen.add(member.name)
            if member.isdir():
                directories+=1
                if member.name in expected:
                    row=expected[member.name];assert row.get('type')=='dir' and member.mode==row['mode']
                continue
            assert member.isfile();row=expected[member.name];assert member.mode==row['mode'] and member.size==row['bytes']
            f=tf.extractfile(member);h=sha256();size=0
            while True:
                chunk=f.read(1<<20)
                if not chunk:break
                h.update(chunk);size+=len(chunk)
            assert h.hexdigest()==row['sha256'] and size==row['bytes']
            count+=1;total+=size
    assert set(expected)<=seen and count==sum(r.get('type')!='dir' for r in rows)
    raw=archive.read_bytes();result=dict(archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),
        manifest_sha256=sha256(manifest_raw).hexdigest(),file_members=count,directory_members=directories,original_bytes=total,
        every_original_file_bytes_sha256_and_mode_verified=True,elapsed_ns=time.monotonic_ns()-started,
        scope='INDEPENDENT_ORIGINAL_ARCHIVE_READBACK_NOT_NEW_QUALIFICATION')
    (OUT/(label+'-root-readback.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    compressed=lzma.compress(manifest_raw);assert lzma.decompress(compressed)==manifest_raw
    (OUT/(label+'-original-member-manifest.json.xz')).write_bytes(compressed)
    (OUT/(label+'-manifest-compression.json')).write_text(json.dumps(dict(original_bytes=len(manifest_raw),original_sha256=sha256(manifest_raw).hexdigest(),
        compressed_bytes=len(compressed),compressed_sha256=sha256(compressed).hexdigest(),decompression_exact=True),indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,sort_keys=True),flush=True)
