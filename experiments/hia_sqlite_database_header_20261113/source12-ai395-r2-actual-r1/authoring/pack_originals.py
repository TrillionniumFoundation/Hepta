"""Archive already-closed Header Source12 originals and static C references.
No product import, generation, VM, compiler, C/native call or original test.
"""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,tarfile,time
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
S=P/'sqlite-database-header-source-r2'
A=P/'sqlite-database-header-source12-actual-r2'
AUD=P/'sqlite-database-header-source12-actual-audit-r1'
OUT=P/'sqlite-database-header-source12-actual-publication-r1'
PAY=OUT/'payload'
PARENT='2cb2861bb8b836cf86997cf06152c1361a775e9f'
PREFIX='experiments/hia_sqlite_database_header_20261113/source12-ai395-r2-actual-r1'
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path):
    path=Path(path);s=path.lstat()
    assert path.resolve()==path and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=64<<20
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as f:
        assert ident(os.fstat(f.fileno()))==ident(s);raw=f.read();assert ident(os.fstat(f.fileno()))==ident(s)
    assert ident(path.lstat())==ident(s) and len(raw)==s.st_size
    return raw,{'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'identity':ident(s)}
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def create(path,raw):
    if not isinstance(raw,bytes):raw=wire(raw)
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    actual,pin=read(path);assert actual==raw
    return pin
started=time.monotonic()
PAY.mkdir(mode=0o700,parents=True,exist_ok=False)
raw,ap=read(AUD/'READBACK.json')
assert ap['sha256']=='4220e47844c209ce2ccf8a8127ea5137d393284ad8bbe389c35bb6bc01e5887a'
audit=json.loads(raw)
assert audit['status']=='PASS_READBACK_SOURCE12_VM_ONLY' and audit['closed_before_child_read']is True and audit['errors']==[] and audit['check_count']==26034
qraw,qp=read(S/'REQUEST.json')
assert qp['sha256']=='be3b92c8190acfeaca8465f90cb4e8e56491ad4c8d5f64e85e837dd51076426d'
rows=[];data={};dirs=[]
def add(path,arc):
    assert arc not in data and not arc.startswith('/') and '..'not in Path(arc).parts
    body,pin=read(path);data[arc]=body;rows.append({'archive_path':arc,'kind':'regular',**pin});return pin
for tag,root in [('frozen-source-request',S),('actual',A),('independent-audit',AUD)]:
    for parent,children,names in os.walk(root,followlinks=False):
        for name in children:
            p=Path(parent)/name;s=p.lstat();assert stat.S_ISDIR(s.st_mode)and p.resolve()==p
            dirs.append({'path':str(p),'archive_path':tag+'/'+str(p.relative_to(root)),'identity':ident(s)})
        for name in sorted(names):add(Path(parent)/name,tag+'/'+str((Path(parent)/name).relative_to(root)))
for name,sha in [
 ('root-database-header-generation-source12-r2-INTENT.json','c10d1ef8d61ecfa047289d95f800b6a775b4dc4066185eace1df7ef331366d86'),
 ('root-database-header-generation-source12-r2-OWNER-READBACK.json','d47e77bf8687248bea0bf833b96fa960798403fe3948357a6eacb22165728a84'),
 ('root-database-header-generation-source12-r2-HJOB.json','ce78e24d5bf696fa283b8a3c8401955305480f81b4ad4b98688dd726c0ed5ecf')]:
    p=add(P/name,'root-originals/'+name);assert p['sha256']==sha
for name in ('audit_database_header_source12_actual_r1.py','header-source12-audit-r1-INTENT.json','header-source12-audit-r1-HJOB.json',
             'review_header_C_sources_r1.py','header-C-peer-r1-INTENT.json','header-C-peer-r1-HJOB.json'):
    add(P/name,'authoring/'+name)
add(P/'header-C-static-peer-r1/REVIEW.json','static-C/PEER-REVIEW.json')
add(P/'root-database-header-oracle-draft-r1.json','static-C/ORACLES.json')
for version in ('3.46.0','3.53.2'):
    add(P/('root-database-header-oracle-sqlite-'+version+'-r1.c'),'static-C/sqlite-'+version+'/adapter.c')
    for name in ('btreeInt.h.original','btree.h.original','util.c.original','sqliteInt.h.original','sqlite.h.in.original'):
        add(P/'sqlite-btree-cell-native-r1/candidate/reference'/('sqlite-'+version)/name,'static-C/reference/sqlite-'+version+'/'+name)
add(Path(__file__).resolve(),'authoring/pack_originals.py')
rows.sort(key=lambda r:r['archive_path']);dirs.sort(key=lambda r:r['archive_path'])
actual=[r for r in rows if r['archive_path'].startswith('actual/')]
assert len(actual)==len(audit['actual_files'])==21 and sum(x['bytes']for x in actual)==3872530
for old in audit['actual_files']:
    now=next(x for x in actual if x['archive_path']=='actual/'+old['relative'])
    assert all(now[k]==old[k]for k in ('path','bytes','sha256','identity'))
for old in json.loads(qraw)['inputs']:
    if old['path'].startswith(str(S)+'/'):
        now=next(x for x in rows if x['path']==old['path'])
        assert all(now[k]==old[k]for k in ('path','bytes','sha256','identity'))
peer=json.loads(data['static-C/PEER-REVIEW.json'])
assert peer['status']=='STATIC_PEER_CLEAR_LIMITED_C_SOURCE' and peer['checks']==152 and peer['errors']==[]
manifest={'schema':'hia.database-header.source12-request-and-actual-originals.v1','status':'SOURCE12_VM_PASS_ONLY',
 'sole_parent':PARENT,'request_saved_to_Git_after_actual':True,'request_preexecution_Git_commit':None,
 'actual_before_first_Git_publication':True,'request':qp,'files':rows,'directories_observed':dirs,
 'file_count':len(rows),'bytes':sum(x['bytes']for x in rows),'actual_files':21,'actual_bytes':3872530,
 'no_execution_by_archiver':True,'static_C_compiled_or_loaded':False}
mp=create(OUT/'ORIGINALS-MANIFEST.json',manifest);mraw,_=read(OUT/'ORIGINALS-MANIFEST.json')
plainio=io.BytesIO()
with tarfile.open(fileobj=plainio,mode='w',format=tarfile.PAX_FORMAT)as tf:
    for row in rows:
        body=data[row['archive_path']];s=row['identity'];i=tarfile.TarInfo(row['archive_path'])
        i.size=len(body);i.mode=stat.S_IMODE(s[2]);i.uid=s[3];i.gid=s[4];i.mtime=s[7]//1000000000
        i.pax_headers={'mtime':str(s[7]//1000000000)+'.'+str(s[7]%1000000000).zfill(9)}
        tf.addfile(i,io.BytesIO(body))
    i=tarfile.TarInfo('ORIGINALS-MANIFEST.json');i.size=len(mraw);i.mode=0o400;i.mtime=0
    tf.addfile(i,io.BytesIO(mraw))
plain=plainio.getvalue();packed=gzip.compress(plain,compresslevel=6,mtime=0)
zp=create(OUT/'ORIGINALS.tar.gz',packed)
again,_=read(OUT/'ORIGINALS.tar.gz');assert gzip.decompress(again)==plain
expected={**data,'ORIGINALS-MANIFEST.json':mraw};seen=set();byname={x['archive_path']:x for x in rows}
with tarfile.open(fileobj=io.BytesIO(again),mode='r:gz')as tf:
    for member in tf:
        assert member.isfile()and member.name in expected and member.name not in seen
        body=tf.extractfile(member).read();assert body==expected[member.name];seen.add(member.name)
        if member.name in byname:
            s=byname[member.name]['identity']
            assert (member.mode,member.uid,member.gid)==(stat.S_IMODE(s[2]),s[3],s[4])
            assert member.pax_headers['mtime']==str(s[7]//1000000000)+'.'+str(s[7]%1000000000).zfill(9)
assert seen==set(expected)
parts=[];restored=bytearray()
for number,offset in enumerate(range(0,len(again),180000)):
    body=again[offset:offset+180000];rel='archive/part-%04d.base64'%number
    pp=create(PAY/rel,base64.b64encode(body)+b'\n');part,_=read(PAY/rel)
    decoded=base64.b64decode(part.rstrip(b'\n'),validate=True);assert decoded==body;restored.extend(decoded)
    parts.append({'relative':rel,'offset':offset,'decoded_bytes':len(body),'decoded_sha256':hashlib.sha256(body).hexdigest(),'ascii_pin':pp})
assert bytes(restored)==again
archive_report={'schema':'hia.database-header.source12-archive-readback.v1','status':'PASS_FULL_RAW_ARCHIVE_READBACK',
 'manifest':mp,'archive':zp,'uncompressed_tar_bytes':len(plain),'uncompressed_tar_sha256':hashlib.sha256(plain).hexdigest(),
 'members':len(seen),'original_files':len(rows),'original_bytes':manifest['bytes'],'actual_files':21,'actual_bytes':3872530,
 'parts':parts,'all_full_bodies_modes_uid_gid_nanosecond_mtime_equal':True,'combined_base64_restore_sha256':hashlib.sha256(restored).hexdigest(),
 'request_first_Git_publication_after_actual':True,'product_reexecuted':False,'seconds':time.monotonic()-started}
arp=create(PAY/'ARCHIVE-READBACK.json',archive_report)
create(PAY/'ORIGINALS-MANIFEST.json',mraw);create(PAY/'INDEPENDENT-READBACK.json',data['independent-audit/READBACK.json'])
selected=[
 'REQUEST.json','LAUNCH.json','STATIC-FREEZE.json','README.md','SOURCE-CANDIDATE.json','CONTROL-DELTA.json','DRAFT-HANDOFF.json',
 'control/source12.py','control/clean_exec.py','control/process_owner_impl.py',
 'inputs/hepta/hia_sqlite_database_header_abi.json','inputs/hepta/hia_sqlite_database_header_native.py',
 'inputs/tools/generate_hia_sqlite_database_header.py','inputs/tests/test_hia_sqlite_database_header_source.py',
 'reference/UPSTREAM.json','reference/sqlite-3.46.0/lockBtree.original.inc','reference/sqlite-3.53.2/lockBtree.original.inc']
for rel in selected:create(PAY/'frozen-source-request'/rel,data['frozen-source-request/'+rel])
for rel in ('FINAL.json','owner.json','owner.json.request.json','OWNER-WRAPPER.json','tests/REPORT.json','tests/sqlite_database_header.hiaasm','tests/unittest.log'):
    create(PAY/'actual'/rel,data['actual/'+rel])
for rel,body in data.items():
    if rel.startswith('root-originals/')or rel.startswith('authoring/')or rel in ('static-C/PEER-REVIEW.json','static-C/ORACLES.json','static-C/sqlite-3.46.0/adapter.c','static-C/sqlite-3.53.2/adapter.c'):
        create(PAY/rel,body)
handoff={
 'schema':'hia.database-header.source12-combined-handoff.v1','status':'PASS_SOURCE12_VM_AND_FULL_READBACK_ONLY',
 'sole_parent':PARENT,'prefix':PREFIX,'frozen_source_root':str(S),'actual_root':str(A),
 'publication_history':{'request_locally_frozen_before_execution':True,'request_preexecution_Git_commit':None,
   'request_and_actual_first_Git_publication_together_after_actual':True,'no_recreated_preexecution_history':True},
 'request':qp,'source12':{'methods':12,'VM_returns':670,'semantic_decisions':634,'protocol_refusals':36,'post_return_custody_faults':6,
 'ids':audit['tests']['ids'],'worker_seconds':audit['tests']['worker_seconds'],'owner':audit['owner'],'zero_all_anomalies':True},
 'independent_audit':{'pin':ap,'checks':26034,'errors':0,'full_21_actual_bytes':3872530,
 'full_physical_source_count':1686,'full_physical_source_bytes':40890650,'full_frozen_inputs':26,'entire_VM_spans':True},
 'archive':archive_report,'static_C':{'peer_status':peer['status'],'checks':152,'versions':['3.46.0','3.53.2'],'sections_each':14,
 'compiled':False,'loaded':False,'C_calls':0,'future_native634_each_not_executed':True},
 'scope':['Header source/Core VM only','Current Pager/WAL/locking/database IO are requests or success-only C fixtures, not actual effects.',
 'No native/C/SQL/transaction/durability/default AgentStore activation qualification.','No old product test or owner replay.']}
create(PAY/'HANDOFF.json',handoff)
files=[]
for path in sorted(PAY.rglob('*')):
    if path.is_file():
        _,pin=read(path);rel=str(path.relative_to(PAY));files.append({'relative':rel,'path':PREFIX+'/'+rel,'mode':'100644','local_path':str(path),**{k:pin[k]for k in ('bytes','sha256','git_blob_sha1')}})
plan={'schema':'hia.database-header.source12-actual-publication-plan.v1','sole_parent':PARENT,'parent_tree':'889b4190fae6c8e0b32d7fb17b14f52571813678','prefix':PREFIX,
 'files':files,'file_count':len(files),'bytes':sum(x['bytes']for x in files),'Git_publication_after_actual':True,'no_product_reexecution':True}
create(OUT/'PLAN.json',plan)
print(json.dumps({'status':'PACKED_ALL_ORIGINALS_READBACK_PASS','files':len(rows),'members':len(seen),'original_bytes':manifest['bytes'],
 'archive':zp,'parts':len(parts),'payload_files':len(files),'payload_bytes':plan['bytes'],'plan':str(OUT/'PLAN.json')},sort_keys=True))
