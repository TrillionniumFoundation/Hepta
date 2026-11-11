"""Independent complete streaming readback of peer originals; no reruns."""
from pathlib import Path
from hashlib import sha256
import json,lzma,tarfile,time
ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r8'
COMPARE=Path('/workspace/scratch/hia-audit-runtime-recovery-20261111/namespace-reconstruction/compare-r1-complete-01')
items=[
    ('namespace-comparison',COMPARE/'namespace-comparison-r1-development.tar.xz',COMPARE/'custody.json','members','name','CUSTODY.json'),
    ('composite-elf-continuation',ROOT/'hia-composite-native-elf-continuation-r2.tar.xz',ROOT/'hia-composite-native-elf-continuation-r2.tar.members.json',None,'path',None),
    ('single-render',ROOT/'hia-edit-render-single-r1-development.tar.xz',ROOT/'hia-edit-render-single-r1-development.tar.xz.custody.json','members','path',None),
]
for label,archive,manifest,key,path_key,extra in items:
    started=time.monotonic_ns();manifest_raw=manifest.read_bytes();value=json.loads(manifest_raw)
    rows=value[key] if key else value;expected={row[path_key]:row for row in rows};assert len(expected)==len(rows)
    seen=set();count=0;total=0
    with tarfile.open(archive,'r|xz') as tf:
        for member in tf:
            assert member.isfile() and member.name not in seen;seen.add(member.name)
            f=tf.extractfile(member);h=sha256();size=0
            if member.name==extra:
                raw=f.read();assert raw==manifest_raw;h.update(raw);size=len(raw)
                assert member.mode==0o600
            else:
                row=expected[member.name];assert member.mode==row['mode'] and member.size==row['bytes']
                while True:
                    chunk=f.read(1<<20)
                    if not chunk:break
                    h.update(chunk);size+=len(chunk)
                assert h.hexdigest()==row['sha256'] and size==row['bytes']
            count+=1;total+=size
    assert seen==set(expected)|({extra} if extra else set())
    raw=archive.read_bytes()
    result=dict(archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),
                manifest_sha256=sha256(manifest_raw).hexdigest(),members=count,original_bytes=total,
                every_original_member_bytes_sha256_and_mode_verified=True,elapsed_ns=time.monotonic_ns()-started,
                scope='INDEPENDENT_ORIGINAL_ARCHIVE_READBACK_NOT_A_NEW_QUALIFICATION')
    (OUT/(label+'-root-readback.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,sort_keys=True),flush=True)
    if label=='single-render':
        compressed=lzma.compress(manifest_raw);assert lzma.decompress(compressed)==manifest_raw
        (OUT/'single-render-r1-custody.json.xz').write_bytes(compressed)
        (OUT/'single-render-custody-compression.json').write_text(json.dumps(dict(original_bytes=len(manifest_raw),original_sha256=sha256(manifest_raw).hexdigest(),compressed_bytes=len(compressed),compressed_sha256=sha256(compressed).hexdigest(),decompression_exact=True),indent=2,sort_keys=True)+'\n')
