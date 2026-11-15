"""Transport the already sealed complete R11 raw; never rerun its sealer."""
from pathlib import Path
import base64, hashlib, json, os, stat, zlib

ROOT=Path(__file__).resolve().parent
SOURCE=Path('/workspace/hia-r11-controls-complete-custody-r1-dda7')
META=Path('/tmp/hia-progress-v152-20261115-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def enc(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def stamp(p):return [getattr(p.lstat(),key) for key in FIELDS]
def read(p):
    p=Path(p);before=stamp(p);s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    for parent in p.parents:assert stat.S_ISDIR(parent.lstat().st_mode)
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        assert [getattr(os.fstat(fd),key) for key in FIELDS]==before
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(s.st_size+1)
        assert len(raw)==s.st_size and [getattr(os.fstat(fd),key) for key in FIELDS]==before==stamp(p)
    finally:os.close(fd)
    return raw,stat.S_IMODE(s.st_mode),before
def write(name,raw):
    p=ROOT/name;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(raw)
    p.chmod(0o644);assert read(p)[0]==raw
    return {'mount':name,'path':str(p),'identity':dict(pin(raw),mode=0o644)}

report_raw,report_mode,report_stat=read(SOURCE/'REPORT.json');report=json.loads(report_raw)
archive,archive_mode,archive_stat=read(SOURCE/'COMPLETE-ORIGINALS.tar.gz')
assert pin(archive)==report['archive']=={'bytes':13437001,'git_blob':'b89d1acf6abe5b5a1d8bd3b91d643c08110857cf','sha256':'920cc0a2e6d7ba7fd4c15c43749e3db0c80670159acfa73ef7dbaa1474aca9e0'}
assert report['all_files']==2221 and report['logical_bytes']==1122135347
assert report['original_qualification']=='FAIL' and report['status']=='PASS_COMPLETE_ORIGINAL_BYTES_AND_MODES'
leaves=[];parts=[];extra=[]
for index,offset in enumerate(range(0,len(archive),393216)):
    raw=archive[offset:offset+393216]
    row=write('parts/%03d.json'%index,enc({'schema':'hia.R11.complete-raw.part.v1','index':index,'offset':offset,
        'archive':report['archive'],'encoding':'base64','decoded':pin(raw),'data':base64.b64encode(raw).decode()}))
    leaves.append(row);parts.append(dict(row,index=index,offset=offset,decoded=pin(raw)))
for name in ('MANIFEST.json','INTENT.json'):
    raw,mode,st=read(SOURCE/name);compressed=zlib.compress(raw,9)
    if name=='MANIFEST.json':assert pin(raw)==report['manifest']
    row=write(name[:-5]+'.zlib.json',enc({'schema':'hia.R11.complete-raw.text-wrapper.v1',
        'original_path':str(SOURCE/name),'original_name':name,'original':pin(raw),'original_mode':mode,
        'original_seven_stats':st,'encoding':'zlib-base64','compressed':pin(compressed),'data':base64.b64encode(compressed).decode()}))
    leaves.append(row);extra.append(row)
paths=[p for p in sorted(SOURCE.rglob('*')) if p.is_file() and p.name not in ('COMPLETE-ORIGINALS.tar.gz','MANIFEST.json','INTENT.json')]
for p in paths:
    raw,mode,st=read(p);name='sealer/'+p.relative_to(SOURCE).as_posix()
    row=write(name,raw);row['original']={'path':str(p),'identity':dict(pin(raw),mode=mode),'seven_stats':st}
    leaves.append(row);extra.append(row)
for name in ('R11-ACTUAL-CUSTODY-SEAL-EXEC.json','R11-ACTUAL-CUSTODY-SEAL-POLL01.json','R11-ACTUAL-CUSTODY-SEAL-RETURN.json',
    'R11-ACTUAL-TERMINAL-READER-EXEC.json','R11-ACTUAL-TERMINAL-READER-RETURN.json',
    'R11-ACTUAL-TERMINAL-READER-ROOT-REVIEW-EXEC.json','R11-ACTUAL-TERMINAL-READER-ROOT-REVIEW.json'):
    p=META/name;raw,mode,st=read(p);row=write('root/'+name,raw)
    row['original']={'path':str(p),'identity':dict(pin(raw),mode=mode),'seven_stats':st}
    leaves.append(row);extra.append(row)
p=Path('/workspace/hia-r11-controls-terminal-readback-r1-dda7/RESULT.json')
raw,mode,st=read(p);assert pin(raw)['git_blob']=='ba8bfe7329ba26b9f7e3d6b742b02d856c2844de'
row=write('terminal/RESULT.json',raw);row['original']={'path':str(p),'identity':dict(pin(raw),mode=mode),'seven_stats':st}
leaves.append(row);extra.append(row)
index={'schema':'hia.R11.complete-raw.transport-index.v1','archive':report['archive'],'archive_original_path':str(SOURCE/'COMPLETE-ORIGINALS.tar.gz'),
    'archive_original_mode':archive_mode,'archive_original_seven_stats':archive_stat,'manifest':report['manifest'],'parts':parts,'metadata':extra,
    'logical_files':2221,'logical_bytes':1122135347,'unique_objects':1295,'unique_bytes':885872197,
    'original_qualification':'FAIL','full_reader_other_outputs_not_in_this_transport':True,
    'source_before_after_originals_retained':True,'products':0,'refs':0,'deletions':0}
leaves.append(write('TRANSPORT-INDEX.json',enc(index)))
for name in ('prepare_transport.py','readback_remote.py'):
    raw,mode,st=read(ROOT/name);leaves.append({'mount':name,'path':str(ROOT/name),'identity':dict(pin(raw),mode=mode)})
assert len({row['mount'] for row in leaves})==len(leaves)
assert all(row['identity']['bytes']<=650000 for row in leaves)
write('PUBLISH-PLAN.json',enc({'schema':'hia.R11.complete-raw.publication-plan.v1','leaves':leaves,'refs':0,'products':0,'deletions':0}))
print(json.dumps({'parts':len(parts),'leaves':len(leaves),'archive':report['archive'],'logical_files':2221,'products':0,'refs':0},sort_keys=True))
