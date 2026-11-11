"""Retain original full-phase A/B evidence and verify every container byte."""
from pathlib import Path
from hashlib import sha256
import json,os,stat,tarfile

base=Path('/workspace/scratch/e26ed3e2edcf')
source=base/'linked-observer-signed-ab-r2'
archive=base/'linked-observer-signed-ab-r2-originals.tar.gz'
receipt=base/'linked-observer-signed-ab-r2-retention.json'
paths={p.relative_to(source).as_posix():p for p in sorted(source.rglob('*')) if p.is_file()}
for name in ('linked-observer-signed-phase-ab.py','linked-observer-signed-phase-ab-r2.py',
 'linked-observer-signed-compare-r2.py','linked-observer-signed-ab-original-r2.log',
 'linked-observer-signed-ab-native-r2.log','linked-observer-existing-controls-r1.log'):
    paths['controls/'+name]=base/name
records={}
for name,path in paths.items():
    st=path.lstat();assert stat.S_ISREG(st.st_mode)
    records[name]={'bytes':st.st_size,'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,
                   'sha256':sha256(path.read_bytes()).hexdigest()}
assert not archive.exists() and not receipt.exists()
with tarfile.open(archive,'w:gz',compresslevel=6) as packed:
    for name,path in paths.items():packed.add(path,arcname=name,recursive=False)
with archive.open('rb') as f:os.fsync(f.fileno())
seen=set();read_bytes=0
with tarfile.open(archive,'r:gz') as packed:
    for member in packed:
        assert member.isfile() and member.name not in seen
        seen.add(member.name);expected=records[member.name]
        assert (member.size,member.mode,member.uid,member.gid)==tuple(expected[k] for k in ('bytes','mode','uid','gid'))
        digest=sha256()
        with packed.extractfile(member) as stream:
            for block in iter(lambda:stream.read(1<<20),b''):digest.update(block);read_bytes+=len(block)
        assert digest.hexdigest()==expected['sha256']
assert seen==set(records)
for name,path in paths.items():
    st=path.lstat();expected=records[name]
    assert (st.st_size,stat.S_IMODE(st.st_mode),st.st_uid,st.st_gid)==tuple(expected[k] for k in ('bytes','mode','uid','gid'))
    assert sha256(path.read_bytes()).hexdigest()==expected['sha256']
result={'schema':'hia.linked-observer.full-development-evidence-retention.v1','scope':'Original A/B only; not cold qualification',
 'archive':str(archive),'archive_bytes':archive.stat().st_size,'archive_sha256':sha256(archive.read_bytes()).hexdigest(),
 'member_count':len(records),'members':records,'every_member_independently_read':True,
 'member_bytes_read':read_bytes,'actual_mode_uid_gid_checked':True,'source_before_after_equal':True,
 'inner_phase_ZIPs':'Each complete original stage archived and every original member read back by unchanged archive_completed_stage before retirement; exact resulting ZIP bytes included here'}
with receipt.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({k:v for k,v in result.items() if k!='members'},sort_keys=True))
