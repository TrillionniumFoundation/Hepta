"""Complete immutable metadata development originals and r13 publication receipts."""
from hashlib import sha256
import io
import json
import lzma
from pathlib import Path
import stat
import tarfile
import time

OUT=Path(__file__).resolve().parent; BASE=OUT.parent; started=time.monotonic_ns()
paths=[p for p in (BASE/'native-program-service-next').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
paths += [BASE/'recovery-completed-r13'/name for name in ('publication.json','parts-remote-readback.json',
    'retire_published_transport_parts.py','parts-verified-before-removal.json','parts-retirement.json','parts-retirement.log')]
rows=[]
for path in sorted(paths):
    assert not path.is_symlink()
    raw=path.read_bytes(); info=path.stat()
    rows.append(dict(path=path.relative_to(BASE).as_posix(),source=str(path),bytes=len(raw),
        mode=stat.S_IMODE(info.st_mode),sha256=sha256(raw).hexdigest(),inode=info.st_ino,mtime_ns=info.st_mtime_ns))
index=OUT/'root-metadata-index.json'; assert not index.exists()
index.write_text(json.dumps(dict(schema='hia-native-metadata-complete-originals-v1',files=rows,
    scope='FULL_METADATA_DIRECTORY_ALL_FAILED_ORIGINALS_AND_R13_PUBLICATION_DUPLICATE_RETIREMENT'),indent=2,sort_keys=True)+'\n')
index_raw=index.read_bytes(); archive=OUT/'root-metadata-development.tar.xz'; assert not archive.exists()
with lzma.open(archive,'wb',preset=1) as sink,tarfile.open(fileobj=sink,mode='w|') as tar:
    item=tarfile.TarInfo('MANIFEST.json'); item.size=len(index_raw); item.mode=0o644
    tar.addfile(item,io.BytesIO(index_raw))
    for row in rows:
        path=Path(row['source']); raw=path.read_bytes(); info=path.stat()
        assert (info.st_ino,info.st_mtime_ns,len(raw),sha256(raw).hexdigest(),stat.S_IMODE(info.st_mode))==(row['inode'],row['mtime_ns'],row['bytes'],row['sha256'],row['mode'])
        item=tarfile.TarInfo(row['path']); item.size=len(raw); item.mode=row['mode'];tar.addfile(item,io.BytesIO(raw))
expected={r['path']:r for r in rows}; seen=set(); total=0; logical=0; cas=0
import zlib
with tarfile.open(archive,'r|xz') as tar:
    for item in tar:
        assert item.isfile() and item.name not in seen;seen.add(item.name)
        raw=tar.extractfile(item).read()
        if item.name=='MANIFEST.json':assert raw==index_raw and item.mode==0o644;continue
        row=expected[item.name]
        assert (len(raw),sha256(raw).hexdigest(),item.mode)==(row['bytes'],row['sha256'],row['mode'])
        path=Path(row['source']);assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==item.mode
        total+=len(raw)
        if '/cas/' in item.name and item.name.endswith('.zlib'):
            expanded=zlib.decompress(raw);assert sha256(expanded).hexdigest()==Path(item.name).stem
            logical+=len(expanded);cas+=1
assert seen==set(expected)|{'MANIFEST.json'}
raw=archive.read_bytes(); receipt=dict(status='PASS',scope='COMPLETE_NATIVE_METADATA_DEVELOPMENT_ONLY',
    archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),
    index=str(index),index_sha256=sha256(index_raw).hexdigest(),members=len(seen),original_files=len(rows),
    original_bytes=total,all_original_bytes_mode_sha_and_live_readback_equal=True,
    logical_CAS_objects=cas,logical_CAS_bytes=logical,all_CAS_lossless_reassembly_hash_verified=True,
    elapsed_ns=time.monotonic_ns()-started,whole_stack_closed=False)
(OUT/'root-metadata-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps(receipt,sort_keys=True),flush=True)
