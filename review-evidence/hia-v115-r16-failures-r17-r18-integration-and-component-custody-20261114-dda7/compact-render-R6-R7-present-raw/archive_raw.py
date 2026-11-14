"""Lossless fixed-plan custody; no product imports or executions."""
from pathlib import Path, PurePosixPath
import gzip
import hashlib
import io
import json
import stat
import tarfile
import time

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'attempt-r1'
PLAN=ROOT/'plan-r1/PLAN.json'

def encode(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def identity(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def put(path,raw):
    with path.open('xb') as stream:stream.write(raw)
def verify(path,row):
    st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)
    assert stat.S_IMODE(st.st_mode)==row['mode']
    raw=path.read_bytes()
    assert identity(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
    return raw

def main():
    OUT.mkdir(exist_ok=False)
    start=time.monotonic_ns();plan_raw=PLAN.read_bytes();plan=json.loads(plan_raw)
    assert identity(plan_raw)['git_blob']=='429638ef862d840aac42bf6b318aa63847abe941'
    rows=plan['entries'];assert len(rows)==272 and sum(row['bytes'] for row in rows)==100388719
    files={};objects={};aliases={}
    for row in rows:
        name=row['path'];safe=PurePosixPath(name)
        assert not safe.is_absolute() and '..' not in safe.parts and str(safe)==name
        assert safe.parts[0] in ('R6','R7') and name not in files
        path=Path(row['original']);raw=verify(path,row)
        files[name]={k:row[k] for k in ('bytes','sha256','git_blob','mode')}
        digest=row['sha256']
        if digest in objects:assert raw==objects[digest].read_bytes()
        else:objects[digest]=path
        aliases.setdefault(digest,[]).append(name)
    assert len(objects)==165
    manifest={'schema':'hia.compact-R6-R7.present-originals-CAS.v1',
        'files':files,'logical_files':272,'logical_bytes':100388719,
        'unique_objects':165,'unique_bytes':53742672,
        'plan':identity(plan_raw),'source_capsules':plan['source_capsules'],
        'prior_R1_R5_full_present_recipe':plan['prior_R1_R5_full_present_recipe'],
        'external_frozen_source_baseline':plan['external_frozen_source_baseline'],
        'scope':'all fixed selected present R6/R7 source changes, authoring, failure receipts, full native/VM buffers and freeze records',
        'R6_result':'native exact normal-return buffers; actual unchanged10M VM fuel FAIL; image557057 does not fit current aggregate',
        'R7_result':'native exact normal-return buffers; actual unchanged10M VM fuel FAIL; image573282 does not fit current aggregate',
        'adopted':False,'prior_missing_R1_originals_remain_missing':True,
        'new_product_executions':0,'new_qualification':False}
    manifest_raw=encode(manifest);put(OUT/'RAW-MANIFEST.json',manifest_raw)
    archive=OUT/'COMPLETE-PRESENT-RAW.tar.gz'
    with archive.open('xb') as target:
        with gzip.GzipFile(filename='',mode='wb',fileobj=target,compresslevel=1,mtime=0) as zipped:
            with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
                entry=tarfile.TarInfo('RAW-MANIFEST.json');entry.size=len(manifest_raw);entry.mode=0o644
                entry.uid=entry.gid=entry.mtime=0;tar.addfile(entry,io.BytesIO(manifest_raw))
                for digest,path in sorted(objects.items()):
                    raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==digest
                    entry=tarfile.TarInfo('objects/'+digest);entry.size=len(raw);entry.mode=0o644
                    entry.uid=entry.gid=entry.mtime=0;tar.addfile(entry,io.BytesIO(raw))
    restored=OUT/'restored';restored.mkdir(exist_ok=False);seen=set()
    with tarfile.open(archive,'r:gz') as tar:
        for item in tar:
            assert item.isreg() and item.uid==item.gid==item.mtime==0 and item.mode==0o644
            assert item.name not in seen;seen.add(item.name)
            raw=tar.extractfile(item).read();assert len(raw)==item.size
            if item.name=='RAW-MANIFEST.json':assert raw==manifest_raw;continue
            assert item.name.startswith('objects/')
            digest=item.name[8:];assert digest in aliases and hashlib.sha256(raw).hexdigest()==digest
            for name in aliases[digest]:
                path=restored/name;path.parent.mkdir(parents=True,exist_ok=True)
                put(path,raw);path.chmod(files[name]['mode'])
    assert seen=={'RAW-MANIFEST.json'}|{'objects/'+key for key in objects}
    assert {p.relative_to(restored).as_posix() for p in restored.rglob('*') if p.is_file()}==set(files)
    for row in rows:
        verify(Path(row['original']),row)
        verify(restored/row['path'],row)
    archive_raw=archive.read_bytes()
    report={'schema':'hia.compact-R6-R7.CAS-full-readback.v1','status':'PASS',
        'logical_files':272,'logical_bytes':100388719,'unique_objects':165,'unique_bytes':53742672,
        'archive':identity(archive_raw),'manifest':identity(manifest_raw),'plan':identity(plan_raw),
        'archive_members':len(seen),'all_archive_members_readback':True,
        'all_272_restored_bytes_fullmode_SHA_Git_match':True,'all_272_original_paths_unchanged':True,
        'restore_directory':str(restored),'elapsed_ns':time.monotonic_ns()-start,
        'new_product_executions':0,'new_qualification':False,'adopted':False,
        'prior_missing_R1_originals_remain_missing':True,'Git_archive_persisted':False}
    put(OUT/'REPORT.json',encode(report));print(json.dumps(report,sort_keys=True),flush=True)

if __name__=='__main__':main()
