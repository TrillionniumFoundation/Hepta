from pathlib import Path
from hashlib import sha256
from decimal import Decimal
import io,json,os,stat,tarfile,time
root=Path('/workspace/scratch/hia-machine-state-native-20261111')
r2=Path('/tmp/hia-machine-state-callers-r2-20261111')
destination=Path('/tmp/hia-machine-state-evidence-20261111')
destination.mkdir(mode=0o700)
pub=destination/'publication'; pub.mkdir(mode=0o700)
sources=[]
for name in ('authoring-r1','preexecution-r1','compile-owner-r1','callers-owner-r1','development-r1','inputs'):
    sources.append((root/name,'r1/'+name))
for name in ('DEVELOPMENT-WORKTREE.json','source-pins-preexecution-r1.json','run-owned-development-r1.py','compile-development-r1.py'):
    sources.append((root/name,'r1/'+name))
sources.extend([(r2,'r2/callers'),(root/'preexecution-r2','r2/preexecution-r2'),
                (root/'source-pins-preexecution-r2.json','r2/source-pins.json'),
                (root/'run-owned-callers-r2.py','r2/run-owned-callers-r2.py')])
peer=Path('/tmp/hia-e26e-authority-page-integration-r1')
for name in ('CODE-STATE-INDEPENDENT-STATIC-REVIEW.json','CODE-STATE-CANONICAL-READBACK.json'):
    sources.append((peer/name,'independent-static-review/'+name))
inputs=[]
for path,name in sources:
    candidates=[path]+sorted(path.rglob('*')) if path.is_dir() else [path]
    for child in candidates:
        archived=name if child==path else name+'/'+child.relative_to(path).as_posix()
        meta=child.lstat()
        if stat.S_ISDIR(meta.st_mode):kind='directory';digest=None
        elif stat.S_ISREG(meta.st_mode):kind='file';digest=sha256(child.read_bytes()).hexdigest()
        else:raise ValueError('unexpected original member type: '+str(child))
        inputs.append({'path':archived,'local_path':str(child),'kind':kind,
                       'bytes':meta.st_size if kind=='file' else 0,
                       'sha256':digest,'mode':stat.S_IMODE(meta.st_mode),
                       'uid':meta.st_uid,'gid':meta.st_gid,'mtime_ns':meta.st_mtime_ns})
assert len({v['path'] for v in inputs})==len(inputs)
manifest={'schema':'hia.machine-state-all-originals.v1','scope':'FIRST_FAIL_AND_CORRECTED_PASS_ORIGINALS',
          'source_commit_r1':'425771d549ebcaa9e1d86fa2dffeffb2de3cb1cd',
          'source_commit_r2':'0d653c0987e941c7f6afb4db67e23fccf854f4e0',
          'members':inputs,'files':sum(x['kind']=='file' for x in inputs),
          'raw_bytes':sum(x['bytes'] for x in inputs)}
(pub/'INVENTORY.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
archive=destination/'originals.tar.xz'
started=time.monotonic()
with tarfile.open(archive,'w:xz',format=tarfile.PAX_FORMAT,preset=6) as tar:
    for row in inputs:
        p=Path(row['local_path']);meta=p.lstat()
        assert stat.S_IMODE(meta.st_mode)==row['mode'] and meta.st_mtime_ns==row['mtime_ns']
        item=tarfile.TarInfo(row['path']);item.mode=row['mode'];item.uid=row['uid'];item.gid=row['gid']
        item.mtime=row['mtime_ns']//1000000000
        item.pax_headers={'mtime':str(Decimal(row['mtime_ns'])/Decimal(1000000000))}
        if row['kind']=='directory':
            item.type=tarfile.DIRTYPE;tar.addfile(item)
        else:
            raw=p.read_bytes();assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256']
            item.size=len(raw);tar.addfile(item,io.BytesIO(raw))
def readback(stream):
    checked=[]
    with tarfile.open(fileobj=stream,mode='r:xz') as tar:
        members=tar.getmembers();assert len(members)==len(inputs)
        for m,row in zip(members,inputs):
            assert m.name.rstrip('/')==row['path']
            assert m.mode==row['mode'] and m.uid==row['uid'] and m.gid==row['gid']
            assert int(Decimal(m.pax_headers['mtime'])*1000000000)==row['mtime_ns']
            if row['kind']=='directory':assert m.isdir()
            else:
                assert m.isfile() and m.size==row['bytes']
                raw=tar.extractfile(m).read()
                assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256']
                assert raw==Path(row['local_path']).read_bytes()
            checked.append(row['path'])
    return len(checked)
with archive.open('rb') as stream:first=readback(stream)
raw=archive.read_bytes();parts=pub/'parts';parts.mkdir(mode=0o700);rows=[]
for n,start in enumerate(range(0,len(raw),524288),1):
    chunk=raw[start:start+524288];p=parts/('part-%03d.bin'%n);p.write_bytes(chunk)
    rows.append({'path':p.relative_to(pub).as_posix(),'bytes':len(chunk),'sha256':sha256(chunk).hexdigest()})
joined=b''.join((pub/row['path']).read_bytes() for row in rows)
assert joined==raw
second=readback(io.BytesIO(joined))
result={'schema':'hia.machine-state-lossless-originals-preservation.v1','status':'PASS',
        'archive_bytes':len(raw),'archive_sha256':sha256(raw).hexdigest(),
        'members':len(inputs),'files':manifest['files'],'raw_bytes':manifest['raw_bytes'],
        'all_original_bytes_equal':True,'all_modes_uid_gid_exact_mtime_ns_equal':True,
        'first_archive_decoder_verified_members':first,'parts_decoder_verified_members':second,
        'parts_join_byte_equal_original_archive':True,'parts':rows,
        'originals_deleted':False,'product_tests_rerun_for_preservation':False,
        'seconds':time.monotonic()-started}
(pub/'PRESERVATION.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:result[k] for k in ('status','archive_bytes','archive_sha256','members','files','raw_bytes','seconds')}),flush=True)
