"""Seal completed root controller/integration revisions without active work."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,lzma,stat,tarfile,time
ROOT=Path(__file__).resolve().parent.parent;OUT=Path(__file__).resolve().parent
started=time.monotonic_ns();files=set()
def include(path):
    path=Path(path)
    if path.is_dir():
        for p in path.rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:files.add(p)
    elif path.is_file():files.add(path)
    else:raise FileNotFoundError(path)
controller=ROOT/'native-edit-controller-next'
include(controller/'tools');include(controller/'docs');include(controller/'examples')
for name in ['actual_program_child.py','main_query_harness.py','test_main_query_r1.py','test_main_query_r2.py','test_main_query_r3.py','compile_main_r3.py','compile_main_r4.py']:
    include(controller/'development'/name)
for stem in ['main-compile-r3','main-compile-r4','main-query-r1','main-query-r2','main-query-r3']:
    include(controller/'development'/stem)
    for suffix in ['.process.json','.stdout.log','.stderr.log']:include(controller/'development'/(stem+'-process'+suffix))
for stem in ['main-query-r1','main-query-r2','main-query-r3']:include(controller/'checkpoints'/stem)
include(ROOT/'native-edit-integrated-next')
for p in controller.glob('*.md'):include(p)
include(Path(__file__))
rows=[]
def digest(p):
    h=sha256();n=0
    with p.open('rb') as f:
        while block:=f.read(1<<20):h.update(block);n+=len(block)
    return n,h.hexdigest()
for p in sorted(files):
    assert not p.is_symlink();s=p.stat();size,h=digest(p)
    assert size==s.st_size
    rows.append(dict(path=p.relative_to(ROOT).as_posix(),source=str(p),bytes=size,sha256=h,mode=stat.S_IMODE(s.st_mode)))
manifest=dict(schema='hia.completed-root-development-originals.v1',files=rows,source_count=len(rows),
    raw_bytes=sum(r['bytes'] for r in rows),scope='MAIN_R3_R4_REAL_MAIN_QUERY_ATTEMPTS_AND_THREE_FIXED_ELF_REVISIONS',
    main_query_r1='FAIL MemoryError after 3 completed cases',main_query_r2='FAIL CPU signal9 after 3 completed cases',
    main_query_r3='PASS 8 cases; complete controller workspaces, unchanged semantic-owner scratch not recaptured',
    fixed_ELF_rejection_cases=8,fixed_ELF_Core_diagnostic_cases=12,fixed_ELF_service_cases=11,
    unchanged_semantic_owner_workspaces_recaptured=False,whole_stack_closed=False)
index=OUT/'root-completed-original-index.json';index.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');iraw=index.read_bytes()
archive=OUT/'root-completed-controller-integration.tar.xz'
with lzma.open(archive,'wb',preset=0) as sink,tarfile.open(fileobj=sink,mode='w|') as tf:
    m=tarfile.TarInfo('MANIFEST.json');m.size=len(iraw);m.mode=0o644;tf.addfile(m,io.BytesIO(iraw))
    for row in rows:
        p=Path(row['source']);info=tarfile.TarInfo(row['path']);info.size=row['bytes'];info.mode=row['mode']
        with p.open('rb') as f:tf.addfile(info,f)
expected={r['path']:r for r in rows};seen=set();total=0
with tarfile.open(archive,'r|xz') as tf:
    for m in tf:
        assert m.isfile() and m.name not in seen;seen.add(m.name)
        f=tf.extractfile(m);h=sha256();n=0
        while block:=f.read(1<<20):h.update(block);n+=len(block)
        if m.name=='MANIFEST.json':assert n==len(iraw) and h.hexdigest()==sha256(iraw).hexdigest() and m.mode==0o644
        else:
            row=expected[m.name];assert (n,h.hexdigest(),m.mode)==(row['bytes'],row['sha256'],row['mode'])
            p=Path(row['source']);assert digest(p)==(n,h.hexdigest()) and stat.S_IMODE(p.stat().st_mode)==m.mode
            total+=n
assert len(seen)==len(rows)+1 and total==manifest['raw_bytes']
raw=archive.read_bytes();receipt=dict(status='PASS',archive=str(archive),archive_bytes=len(raw),archive_sha256=sha256(raw).hexdigest(),
    archive_git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),index=str(index),index_bytes=len(iraw),index_sha256=sha256(iraw).hexdigest(),
    members=len(seen),raw_original_bytes=total,all_original_bytes_modes_and_live_readback_equal=True,
    scope=manifest['scope'],whole_stack_closed=False,elapsed_ns=time.monotonic_ns()-started)
(OUT/'root-completed-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
