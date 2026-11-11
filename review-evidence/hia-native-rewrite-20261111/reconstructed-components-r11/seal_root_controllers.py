"""Freeze completed native controller development and explicit fixture gaps."""
from pathlib import Path
from hashlib import sha256,sha1
import io,json,tarfile,time
root=Path('/workspace/scratch/9acdfa9f5639');src=root/'native-edit-controller-next';out=root/'recovery-completed-r11';start=time.monotonic_ns()
folders=['tools','docs','examples','checkpoints/main-authoring-r1','development/main-compile-r2','development/query-compile-r1','development/query-controller-r1']
paths=set()
for relative in folders:paths.update(p for p in (src/relative).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
for p in src.iterdir():
    if p.is_file() and p.name.startswith(('main-','query-')):paths.add(p)
for p in (src/'development').iterdir():
    if p.is_file() and p.name.startswith(('compile_main_','compile_query_','test_query_','query_controller_','main-','query-')):paths.add(p)
paths=sorted(paths);rows=[]
for p in paths:
    raw=p.read_bytes();rows.append(dict(path=str(p.relative_to(root)),bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=p.stat().st_mode&0o777))
manifest=json.dumps(rows,indent=2,sort_keys=True).encode()+b'\n';archive=out/'root-native-controllers-r1-development.tar.xz';assert not archive.exists()
with tarfile.open(archive,'w:xz',preset=1) as t:
    for p,row in zip(paths,rows):t.add(p,arcname=row['path'],recursive=False)
    m=tarfile.TarInfo('MANIFEST.json');m.size=len(manifest);m.mode=0o644;t.addfile(m,io.BytesIO(manifest))
by_name={r['path']:r for r in rows};seen=set()
with tarfile.open(archive,'r|xz') as t:
    for m in t:
        raw=t.extractfile(m).read()
        if m.name=='MANIFEST.json':assert raw==manifest;continue
        r=by_name[m.name];p=root/m.name;assert m.name not in seen and m.isfile() and m.mode==r['mode'] and len(raw)==r['bytes'] and sha256(raw).hexdigest()==r['sha256']
        assert p.read_bytes()==raw and p.stat().st_mode&0o777==r['mode'];seen.add(m.name)
assert len(seen)==len(rows)
raw=archive.read_bytes();receipt=dict(archive=str(archive),bytes=len(raw),sha256=sha256(raw).hexdigest(),git_sha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
    members=len(rows)+1,original_bytes=sum(r['bytes'] for r in rows),all_original_bytes_modes_and_live_readback_equal=True,
    elapsed_ns=time.monotonic_ns()-start,scope='MAIN_NATIVE_COMPILE_AND_QUERY_NATIVE_TEN_CASES_WITH_EXPLICIT_PRIVATE_PREDECESSOR_FOREIGN_SERVICE_FIXTURES',
    full_native_controller_executable_qualified=False,whole_stack_closed=False)
(out/'root-controller-custody.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True),flush=True)
