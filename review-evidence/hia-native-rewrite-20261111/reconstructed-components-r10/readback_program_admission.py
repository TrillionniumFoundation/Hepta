"""Correct observed original manifest path/schema; preserve prior reader failure."""
from pathlib import Path
from hashlib import sha256
import json,lzma,tarfile,time
ROOT=Path('/workspace/scratch/9acdfa9f5639');OUT=ROOT/'recovery-completed-r10'
archive=ROOT/'hia-program-admission-native-r1-development.tar.xz'
manifest=ROOT/'hia-program-admission-native-r1-development.members.json'
started=time.monotonic_ns();manifest_raw=manifest.read_bytes();rows=json.loads(manifest_raw)['members']
expected={r['path']:r for r in rows};assert len(expected)==len(rows);seen=set();count=0;total=0;directories=0
with tarfile.open(archive,'r|xz') as tf:
    for member in tf:
        assert member.name not in seen;seen.add(member.name);row=expected[member.name];assert member.mode==row['mode']
        if member.isdir():assert row['kind']=='directory';directories+=1;continue
        assert member.isfile() and row['kind']=='file' and member.size==row['bytes']
        f=tf.extractfile(member);h=sha256();size=0
        while True:
            chunk=f.read(1<<20)
            if not chunk:break
            h.update(chunk);size+=len(chunk)
        assert h.hexdigest()==row['sha256'] and size==row['bytes'];count+=1;total+=size
assert set(expected)==seen
raw=archive.read_bytes();result=dict(archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),
    manifest_sha256=sha256(manifest_raw).hexdigest(),file_members=count,directory_members=directories,original_bytes=total,
    every_original_file_bytes_sha256_and_all_member_modes_verified=True,elapsed_ns=time.monotonic_ns()-started,
    scope='INDEPENDENT_ORIGINAL_ARCHIVE_READBACK_NOT_NEW_QUALIFICATION')
(OUT/'program-admission-root-readback.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
compressed=lzma.compress(manifest_raw);assert lzma.decompress(compressed)==manifest_raw
(OUT/'program-admission-original-member-manifest.json.xz').write_bytes(compressed)
(OUT/'program-admission-manifest-compression.json').write_text(json.dumps(dict(original_bytes=len(manifest_raw),original_sha256=sha256(manifest_raw).hexdigest(),
    compressed_bytes=len(compressed),compressed_sha256=sha256(compressed).hexdigest(),decompression_exact=True),indent=2,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True),flush=True)
