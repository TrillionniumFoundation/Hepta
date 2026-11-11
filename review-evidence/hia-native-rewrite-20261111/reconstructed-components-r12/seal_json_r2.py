"""Complete lossless root JSON entry checkpoint; no logical run upgrading."""
from pathlib import Path
from hashlib import sha256
import io,json,lzma,stat,tarfile,time
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent;source=ROOT/'native-edit-json-next'
start=time.monotonic_ns();rows=[]
for p in sorted(source.rglob('*')):
    if not p.is_file() or '__pycache__' in p.parts:continue
    assert not p.is_symlink();raw=p.read_bytes();rows.append(dict(path=p.relative_to(source).as_posix(),source=str(p),
        bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=stat.S_IMODE(p.stat().st_mode)))
index=OUT/'json-r2-original-index.json';index.write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n');iraw=index.read_bytes()
archive=OUT/'root-json-entry-r2-development.tar.xz'
with lzma.open(archive,'wb',preset=0) as sink,tarfile.open(fileobj=sink,mode='w|') as tf:
    i=tarfile.TarInfo('MANIFEST.json');i.size=len(iraw);i.mode=0o644;tf.addfile(i,io.BytesIO(iraw))
    for row in rows:
        p=Path(row['source']);raw=p.read_bytes();assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256']
        i=tarfile.TarInfo(row['path']);i.size=len(raw);i.mode=row['mode'];tf.addfile(i,io.BytesIO(raw))
expected={r['path']:r for r in rows};seen=set();total=0
with tarfile.open(archive,'r|xz') as tf:
    for m in tf:
        assert m.isfile() and m.name not in seen;seen.add(m.name);raw=tf.extractfile(m).read()
        if m.name=='MANIFEST.json':assert raw==iraw and m.mode==0o644
        else:
            row=expected[m.name];assert (len(raw),sha256(raw).hexdigest(),m.mode)==(row['bytes'],row['sha256'],row['mode'])
            p=Path(row['source']);assert p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==m.mode;total+=len(raw)
assert len(seen)==len(rows)+1
raw=archive.read_bytes();receipt=dict(status='PASS',archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),
    index=str(index),index_bytes=len(iraw),index_sha256=sha256(iraw).hexdigest(),members=len(seen),original_bytes=total,
    all_original_bytes_modes_and_live_readback_equal=True,scope='RAW_JSON_ENTRY_R2_17_ACTUAL_CASES_PLUS_UNCHANGED_FAILED_ATTEMPTS',
    whole_stack_closed=False,elapsed_ns=time.monotonic_ns()-start)
(OUT/'json-r2-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
