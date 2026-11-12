"""Read-only seal of completed local development originals, not qualification."""
from pathlib import Path
import hashlib
import io
import json
import lzma
import os
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parent
OUT = Path('/dev/shm/hia-selfbuild-seal-r1')
OUT.mkdir(parents=True, exist_ok=False)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(p):
    st = p.lstat()
    assert stat.S_ISREG(st.st_mode), str(p)
    b = p.read_bytes()
    return dict(path=p.relative_to(ROOT).as_posix(), kind='file', mode=stat.S_IMODE(st.st_mode),
                bytes=len(b), sha256=sha(b), gitsha=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())

began = time.monotonic_ns()
paths = set(ROOT.glob('*.py'))
paths.update(ROOT.joinpath('development').rglob('*'))
paths.update(ROOT.joinpath('authoring-dependencies').rglob('*'))
paths.update(ROOT / p for p in ['B3-35ee.original.image.bin', 'original-matching-cold.json',
                              'reference-kit-r13-manifest.json'])
rows = []
for p in sorted(paths, key=lambda p:p.relative_to(ROOT).as_posix()):
    s = p.lstat()
    if stat.S_ISREG(s.st_mode): rows.append(pin(p))
    else:
        assert stat.S_ISDIR(s.st_mode), str(p)
        rows.append(dict(path=p.relative_to(ROOT).as_posix(), kind='directory', mode=stat.S_IMODE(s.st_mode), bytes=0))
manifest = {'schema':'hia-selfbuilder-development-originals-r1', 'scope':'LOCAL_DEVELOPMENT_NOT_UBUNTU24_QUALIFICATION',
            'rows':rows, 'members':len(rows), 'files':sum(x['kind']=='file' for x in rows),
            'logical_bytes':sum(x['bytes'] for x in rows),
            'external_original_archive':{'gitsha':'248b8ee345013c3fb80d4bd9b7fb9cbfaaa748f6',
                'bytes':57162628,'sha256':'721d89da963f863e3760d9577f3585b0cd9d6f3c71a36ee597d975baf12e388b'},
            'external_original_readback_delivery':'e4eb1c348c60d306f6316aa964fb89e8e551b643',
            'all_completed_failures_retained':True, 'activation':False,
            'exclusions':['unchanged original-r13 already preserved in exact original archive',
                          'unchanged 644 reference-kit copies reconstructible from exact original input kit',
                          'Python interpreter cache files outside selected roots']}
index_raw=(json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
(OUT/'members.json').write_bytes(index_raw)
archive=OUT/'development.tar.xz'
with lzma.open(archive,'wb',preset=1) as compressed:
    with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as tar:
        for row in rows:
            p=ROOT/row['path']; item=tarfile.TarInfo(row['path']);item.mode=row['mode'];item.mtime=0
            if row['kind']=='directory': item.type=tarfile.DIRTYPE;tar.addfile(item)
            else:
                raw=p.read_bytes();assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
                item.size=len(raw);tar.addfile(item,io.BytesIO(raw))
expected={x['path']:x for x in rows};seen=set();logical=0
with tarfile.open(archive,'r|xz') as tar:
    for item in tar:
        assert item.name in expected and item.name not in seen,item.name
        seen.add(item.name);r=expected[item.name]
        assert item.mode==r['mode'] and item.size==r['bytes'], item.name
        if r['kind']=='directory':assert item.isdir()
        else:
            assert item.isfile()
            raw=tar.extractfile(item).read()
            assert sha(raw)==r['sha256'] and len(raw)==r['bytes']
            assert raw==(ROOT/item.name).read_bytes()
            logical+=len(raw)
assert seen==set(expected) and logical==manifest['logical_bytes']
for r in rows:
    p=ROOT/r['path']
    if r['kind']=='file':assert pin(p)==r
    else:assert p.is_dir() and stat.S_IMODE(p.lstat().st_mode)==r['mode']
b=archive.read_bytes()
receipt={'schema':'hia-selfbuilder-development-full-seal-r1','status':'PASS',
         'scope':'READ_ONLY_SEAL_OF_LOCAL_EXECUTION_ORIGINALS',
         'archive':{'path':str(archive),'bytes':len(b),'sha256':sha(b),
                    'gitsha':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()},
         'member_index':{'path':str(OUT/'members.json'),'bytes':len(index_raw),'sha256':sha(index_raw)},
         'members':len(rows),'files':manifest['files'],'logical_bytes':logical,
         'all_archive_members_full_bytes_sha_mode_and_source_after_checked':True,
         'elapsed_ns':time.monotonic_ns()-began,'targets_executed':0,'activation':False}
(OUT/'custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps(receipt,sort_keys=True),flush=True)
