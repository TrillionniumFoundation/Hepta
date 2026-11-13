"""Lossless archive of the one closed WAL snapshot native run; stdlib IO only."""
from pathlib import Path
import base64,decimal,gzip,hashlib,io,json,os,stat,tarfile,time
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
R=P/'sqlite-wal-snapshot-native-r1'
A=P/'sqlite-wal-snapshot-native-r1-actual'
AUD=P/'sqlite-wal-snapshot-native-r1-actual-audit-r2'
PUB=P/'sqlite-wal-snapshot-native-r1-actual-publication-r1'
PREFIX='experiments/hia_sqlite_wal_snapshot_20261113/native-finite-ai395-r1-actual-r1'
PARENT='5362fc690b3b7664c34f5d565089679778bfcf89'
PARENT_TREE='46933d222cc9d71d57f792d9a8af197e06cf0ace'
AUDIT_SHA='df93acb7a839593c181fef452dfb6fe80fd150fbed82e75aa94d8508d3a4ce4f'
def require(v,m):
    if not v:raise RuntimeError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p,limit=64<<20):
    p=Path(p);s=p.lstat()
    require(p.resolve(strict=True)==p and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit,'exact bounded single-link file')
    fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        require(ident(os.fstat(fd))==ident(s),'initial descriptor')
        with os.fdopen(fd,'rb',closefd=False)as f:b=f.read(limit+1)
        require(ident(os.fstat(fd))==ident(s)==ident(p.lstat())and len(b)==s.st_size<=limit,'whole stable original')
    finally:os.close(fd)
    return b,s
def pin(p,limit=64<<20):
    b,s=read(p,limit);return {'path':str(p),'bytes':len(b),'sha256':sha(b),'git_blob':git(b),'identity':ident(s)}
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def put(p,b):
    if not isinstance(b,bytes):b=wire(b)
    p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:f.write(b);f.flush();os.fsync(f.fileno())
    require(read(p)[0]==b,'new publication body independent readback')
    return pin(p)
def collect(root,prefix):
    result={prefix:root}
    for base,dirs,names in os.walk(root,followlinks=False):
        for n in dirs:
            p=Path(base)/n;require(stat.S_ISDIR(p.lstat().st_mode)and p.resolve()==p,'exact directory')
            result[prefix+'/'+str(p.relative_to(root))]=p
        for n in names:
            p=Path(base)/n;result[prefix+'/'+str(p.relative_to(root))]=p
    return result
started=time.monotonic_ns()
require(not PUB.exists(),'fresh actual publication; no rerun')
b,s=read(AUD/'READBACK.json');audit=json.loads(b)
require(sha(b)==AUDIT_SHA and audit['status']=='FINITE_NATIVE_ORIGINALS_INDEPENDENT_READBACK_PASS'
    and audit['errors']==[]and audit['owner_closed']is True and audit['owner_natural']is True
    and audit['product_reexecuted']is False,'complete current owner-first independent readback')
require(audit['trace']['hia']['sha256']=='3cc9223d34768fb1c0062a6e918cec782a749246a6843eed9c0c597f0facecfe'
    and audit['trace']['C']['sha256']=='669fdac758781c872037a68be496a08770d1caa6d1b8a9d650eeff5f1a67cbf3'
    and sum(x['bytes']for x in audit['trace'].values())==203187698,'exact complete two-stream actual')
sources=collect(A,'actual')
actual_names={name[7:]for name,p in sources.items()if p.is_file()}
require(actual_names==set(audit['originals']['files']),'exact actual file population')
for name,pinrow in audit['originals']['files'].items():require(pin(A/name)==pinrow,'actual original unchanged after independent readback')
require(len(actual_names)==audit['originals']['count'] and sum(x['bytes']for x in audit['originals']['files'].values())==audit['originals']['bytes'],'all actual bytes')
for root,tag in [
 (P/'sqlite-wal-snapshot-native-r1-actual-audit-r1','audit-r1-preserved-HOLD'),
 (AUD,'audit-r2'),
 (P/'sqlite-wal-snapshot-native-r1-actual-readback-invocation-r1','audit-invocation-r1'),
 (P/'sqlite-wal-snapshot-native-r1-actual-readback-invocation-r2','audit-invocation-r2')]:
    sources.update(collect(root,tag))
sources['audit-authoring/audit_actual_r1.py']=P/'audit_wal_snapshot_native_r1_actual.py'
sources['audit-authoring/audit_actual_r2.py']=P/'audit_wal_snapshot_native_r1_actual_r2.py'
sources['archive-authoring/pack_actual.py']=Path(__file__).resolve()
root_rows={
'root-wal-snapshot-native-two-c2704-r1-INTENT.json':(9329,'e5d3d3d349c2153092860db82278d57855ddab1fdb4b2f588e50383e2fae097b'),
'root-wal-snapshot-native-two-c2704-r1-OWNER-READBACK.json':(7026,'4d04d441ecf3685a28bcfe08b3d7a5afbc2a37a5ef8f874d361dce4290297791'),
'root-wal-snapshot-native-two-c2704-r1-HJOB.json':(459366,'d37c77b47b09cc9edf40d4e6c53a10a2bdbb4d4a6cd8db691eb492519baa35eb')}
for n,(length,digest)in root_rows.items():
    b,s=read(P/n);require(len(b)==length and sha(b)==digest,'Root immutable full original '+n)
    sources['root-originals/'+n]=P/n
for n in ('REQUEST.json','LAUNCH.json','PREEXEC.json','CONTROL-PINS.json','EXPECTED-MATRIX.json','NEW-C-ORACLES.json'):
    sources['request-reference/'+n]=R/n
rows=[];required_dirs=set()
for name in sources:
    require(not name.startswith('/')and '..'not in Path(name).parts,'safe archive key')
    for d in Path(name).parents:
        if str(d)!='.':required_dirs.add(str(d))
for name in sorted(required_dirs-set(sources)):
    rows.append({'name':name,'kind':'directory','mode':0o700,'uid':os.getuid(),'gid':os.getgid(),
        'mtime_ns':0,'bytes':0,'origin':'virtual transport parent'})
for name,p in sources.items():
    s=p.lstat();row={'name':name,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,
        'mtime_ns':s.st_mtime_ns,'original_path':str(p),'original_identity':ident(s)}
    if stat.S_ISDIR(s.st_mode):row.update(kind='directory',bytes=0)
    else:
        b,s=read(p);row.update(kind='file',bytes=len(b),sha256=sha(b),git_blob=git(b))
    rows.append(row)
rows.sort(key=lambda r:r['name'])
require(len({r['name']for r in rows})==len(rows),'unique all archive members')
PUB.mkdir(mode=0o700);payload=PUB/'payload';payload.mkdir(mode=0o700)
manifest={'schema':'hia.sqlite.wal-snapshot.native-actual-archive.v1','parent_request_commit':PARENT,
    'owner_closed_before_any_child_read':True,'product_execution_by_archiver':False,'members':rows,
    'member_count':len(rows),'file_count':sum(r['kind']=='file'for r in rows),
    'original_bytes':sum(r['bytes']for r in rows),'actual_files':audit['originals']['count'],
    'actual_bytes':audit['originals']['bytes'],'preserved_reader_r1_error':'optional owner_error KeyError; no child read before bound ECHILD',
    'scope':'Finite native WAL snapshot scan and fixed snapshot page location, not SQL or locking/IO/transaction/durability/current-cold qualification.'}
mraw=wire(manifest);mp=put(payload/'ORIGINALS-MANIFEST.json',mraw)
archive=PUB/'ORIGINALS.tar.gz'
with archive.open('xb')as f:
    with gzip.GzipFile(fileobj=f,mode='wb',filename='',mtime=0,compresslevel=6)as gz:
        with tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT)as tf:
            for r in rows:
                t=tarfile.TarInfo(r['name']);t.mode=r['mode'];t.uid=r['uid'];t.gid=r['gid'];t.uname=t.gname=''
                t.mtime=r['mtime_ns']//1000000000
                t.pax_headers={'mtime':str(r['mtime_ns']//1000000000)+'.'+str(r['mtime_ns']%1000000000).zfill(9)}
                if r['kind']=='directory':t.type=tarfile.DIRTYPE;tf.addfile(t)
                else:
                    b,s=read(sources[r['name']])
                    require(len(b)==r['bytes']and sha(b)==r['sha256']and git(b)==r['git_blob']and ident(s)==r['original_identity'],'unchanged archive member before write')
                    t.size=len(b);tf.addfile(t,io.BytesIO(b))
            t=tarfile.TarInfo('ORIGINALS-MANIFEST.json');t.size=len(mraw);t.mode=0o600;t.mtime=0
            tf.addfile(t,io.BytesIO(mraw))
    f.flush();os.fsync(f.fileno())
compressed,_=read(archive,384<<20);parts=[]
for number,start in enumerate(range(0,len(compressed),384000)):
    body=compressed[start:start+384000];encoded=base64.b64encode(body)
    name='archive/part-%04d.base64'%number;p=put(payload/name,encoded)
    parts.append({'path':name,'offset':start,'decoded_bytes':len(body),'decoded_sha256':sha(body),
        'text_bytes':p['bytes'],'text_sha256':p['sha256'],'text_git_blob':p['git_blob']})
restored=b''.join(base64.b64decode(read(payload/r['path'])[0],validate=True)for r in parts)
require(restored==compressed,'complete all-base64 concatenation equals original gzip')
plain_sha=hashlib.sha256();plain_bytes=0
with gzip.GzipFile(fileobj=io.BytesIO(restored),mode='rb')as gz:
    while True:
        block=gz.read(1<<20)
        if not block:break
        plain_sha.update(block);plain_bytes+=len(block)
seen=[];total=0
expected_rows=rows+[{'name':'ORIGINALS-MANIFEST.json','kind':'file','mode':0o600,
    'uid':0,'gid':0,'mtime_ns':0,'bytes':len(mraw),'sha256':sha(mraw),'git_blob':git(mraw)}]
with tarfile.open(fileobj=io.BytesIO(restored),mode='r:gz')as tf:
    for number,member in enumerate(tf):
        require(number<len(expected_rows),'no additional tar members')
        r=expected_rows[number]
        kind='file'if member.isfile()else'directory'if member.isdir()else'REFUSED'
        ns=int(decimal.Decimal(member.pax_headers.get('mtime',str(member.mtime)))*1000000000)
        require((member.name,kind,member.mode,member.uid,member.gid,ns,member.size)==
            (r['name'],r['kind'],r['mode'],r['uid'],r['gid'],r['mtime_ns'],r['bytes']),'complete typed archive metadata')
        require(member.name not in seen,'no duplicate restored member');seen.append(member.name)
        if kind=='file':
            body=tf.extractfile(member).read();total+=len(body)
            original=mraw if member.name=='ORIGINALS-MANIFEST.json'else read(sources[r['name']])[0]
            require(body==original and sha(body)==r['sha256']and git(body)==r['git_blob'],'all original full body SHA and Git restored')
        if 'original_identity'in r:require(ident(sources[r['name']].lstat())==r['original_identity'],'original metadata unchanged after archive')
require(seen==[r['name']for r in rows]+['ORIGINALS-MANIFEST.json'],'all original members restored')
archive_readback={'schema':'hia.sqlite.wal-snapshot.native-archive-readback.v1','status':'FULL_TYPED_ARCHIVE_AND_BASE64_READBACK_PASS',
    'manifest':mp,'archive':pin(archive,384<<20),'parts':parts,'members':len(seen),'body_bytes':total,
    'full_uncompressed_tar_bytes':plain_bytes,'full_uncompressed_tar_sha256':plain_sha.hexdigest(),'gzip_entire_body_and_crc_read':True,
    'all_full_bodies_metadata_and_source_identity_equal':True,'actual_files':audit['originals']['count'],
    'actual_bytes':audit['originals']['bytes'],'new_product_execution':False,'elapsed_ns':time.monotonic_ns()-started}
put(payload/'ARCHIVE-READBACK.json',archive_readback)
direct={'INDEPENDENT-READBACK.json':AUD/'READBACK.json','authoring/audit_actual_r1.py':P/'audit_wal_snapshot_native_r1_actual.py',
'authoring/audit_actual_r2.py':P/'audit_wal_snapshot_native_r1_actual_r2.py','authoring/pack_actual.py':Path(__file__).resolve(),
'history/READER-r1-HOLD.json':P/'sqlite-wal-snapshot-native-r1-actual-audit-r1/READBACK.json',
'actual/FINAL.json':A/'FINAL.json','actual/WORKER.json':A/'WORKER.json','actual/native-REPORT.json':A/'native/REPORT.json',
'actual/lifecycle.json':A/'lifecycle.json','actual/lifecycle.json.request.json':A/'lifecycle.json.request.json',
'actual/OWNER-RETURN.json':A/'OWNER-RETURN.json','actual/HIA-trace-INDEX.json':A/'native/trace/hia/INDEX.json',
'actual/C-trace-INDEX.json':A/'native/trace/C/INDEX.json','actual/COMPILE-RECEIPT.json':A/'hia-compile/snapshot.receipt.json',
'actual/COMPILE-REQUEST.json':A/'hia-compile/snapshot.request.json','actual/COMPILE-STDOUT.json':A/'hia-compile/snapshot.stdout.log'}
for n in root_rows:direct['root-originals/'+n]=P/n
for name,path in direct.items():
    b,s=read(path);b.decode('utf-8');require(len(b)<1<<20,'direct Git text bound');put(payload/name,b)
summary={'schema':'hia.sqlite.wal-snapshot.native-actual-handoff.v1',
'status':'FINITE_NATIVE_13_2704_AND_TWO_C_639_PASS_WITH_INDEPENDENT_FULL_READBACK',
'request_commit':PARENT,'request_tree':PARENT_TREE,'request_sha256':'29f0796711fc5c127fa4b355bfd860f99889bbc6af8b622b229c63625559bfa1',
'actual_root':str(A),'owner_hjob':'1a1d4bc0256-392-561','owner_seconds':180,'cleanup_seconds':3,
'actual_files':audit['originals']['count'],'actual_bytes':audit['originals']['bytes'],'independent_audit':pin(AUD/'READBACK.json'),
'population':audit['population'],'trace':audit['trace'],'original608_complete_spans_equal':audit['all_original608_complete_buffers_equal'],
'C_full_raw_before_projection':audit['C_raw_and_fixed_projection_drives'],'frozen_inputs':audit['frozen_inputs'],
'source':audit['source'],'system':audit['system'],'elapsed':audit['actual_elapsed'],
'original_Source12_methods_unchanged':True,'separate_added_method':{'scenarios':144,'native_returns':2096,'page_sizes':[512,1024,2048,4096,8192,16384,32768,65536]},
'compiler':{'historical_development_B3_sha256':'9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892',
'image_bytes':90138,'image_sha256':'d3df731d19c56848503398571616d153766ef05db2e9f192cbc6bf4be39d9498',
'one_HIA_and_two_C_compiles':True,'each_limits':{'wall_seconds':20,'CPU_seconds':10,'image_bytes':1<<20}},
'archive':{'manifest':mp,'archive':archive_readback['archive'],'member_count':len(seen),'file_count':manifest['file_count'],
'original_bytes':manifest['original_bytes'],'base64_parts':len(parts)},
'reader_r1_schema_error_preserved':True,'new_product_execution_by_auditor_or_archiver':False,
'current_matching_cold_qualified':False,'SQL_locks_IO_transactions_durability_or_default_AgentStore_qualified':False,
'scope':'WAL committed-snapshot scan and fixed-snapshot latest-page location byte algorithms under finite native C comparison only.'}
put(payload/'HANDOFF.json',summary)
files=[]
for path in sorted(payload.rglob('*')):
    if path.is_file():
        b,s=read(path);b.decode('utf-8');require(len(b)<1<<20,'every Git original is bounded UTF8')
        rel=str(path.relative_to(payload));files.append({'relative':rel,'path':PREFIX+'/'+rel,'local_path':str(path),
            'mode':'100644','type':'blob','sha':git(b),'sha256':sha(b),'bytes':len(b)})
plan={'schema':'hia.git.immutable-publication-plan.v1','repository':'TrillionniumFoundation/Hepta',
'parent_commit':PARENT,'parent_tree':PARENT_TREE,'prefix':PREFIX,'files':files,'new_product_execution':False,
'status':'COMPLETE_NATIVE_ACTUAL_READBACK_AND_ARCHIVE_PASS','archive':summary['archive']}
put(PUB/'PLAN.json',plan)
print(json.dumps({'status':plan['status'],'plan':pin(PUB/'PLAN.json'),'new_files':len(files),
'unique_blobs':len({x['sha']for x in files}),'text_bytes':sum(x['bytes']for x in files),'archive':summary['archive']}))
