"""Lossless packaging of already closed failed actuals; no compiler, VM or native calls."""
from pathlib import Path
from contextlib import contextmanager
import base64,gzip,hashlib,io,json,os,stat,tarfile
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
ROOT=P/'varint-native-r2'
ACT=P/'varint-native-r2-actual'
AUDIT=P/'varint-native-r2-independent-audit-r1'
PUB=P/'varint-native-r2-actual-publication-r1'
PREFIX='experiments/hia_sqlite_varint_20261113/native-finite-ai395-r2-actual-failure-r1'
def wire(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
@contextmanager
def parentfd(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in Path(path).parts[1:-1]:
            f=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=f
        yield fd,Path(path).name
    finally:os.close(fd)
def read(path):
    with parentfd(path) as (parent,name):
        before=os.stat(name,dir_fd=parent,follow_symlinks=False)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<64<<20
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            assert identity(before)==identity(os.fstat(fd));pieces=[];n=0
            while True:
                b=os.read(fd,1<<20)
                if not b:break
                pieces.append(b);n+=len(b);assert n<=before.st_size
            assert n==before.st_size and identity(before)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
        finally:os.close(fd)
    raw=b''.join(pieces)
    return {'source_path':str(path),'bytes':len(raw),'sha256':sha(raw),'git_blob':git(raw),'identity':identity(before)},raw
def write(path,raw):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.chmod(path,0o600)
    p,b=read(path);assert b==raw;return p
assert not PUB.exists()
PUB.mkdir(mode=0o700)
sdk={"AUDIT-SCRIPT-WRITE-ACK.json":"{\n  \"content\": [\n    {\n      \"type\": \"text\",\n      \"text\": \"{\\\"mode\\\":384,\\\"sha256\\\":\\\"d74931e6fbb089d77004c7c0b978bc585373d33a4e3e9dcbcade4c61b76ae013\\\",\\\"size\\\":23460,\\\"version\\\":\\\"66306:79479467:23460:1794549754569245736:1794549754569864920\\\",\\\"written\\\":23460}\"\n    }\n  ],\n  \"structuredContent\": null,\n  \"isError\": false\n}\n","AUDIT-RUN-INTENT.json":"{\n  \"host\": \"ai395\",\n  \"command\": \"/usr/bin/python3.14 -I -S -B /home/qq/hia-rewrite-20261113-e26e-r1/audit_varint_native_r2_failure_r1.py\",\n  \"cwd\": \"/home/qq/hia-rewrite-20261113-e26e-r1\",\n  \"idempotency_key\": \"cold-varint-native-r2-closed-failure-readback-r1\",\n  \"timeout_seconds\": 60\n}\n","AUDIT-RUN-ACK.json":"{\n  \"content\": [\n    {\n      \"type\": \"text\",\n      \"text\": \"{\\n  \\\"audit_recorded\\\": true,\\n  \\\"job\\\": {\\n    \\\"args\\\": [\\n      \\\"-c\\\",\\n      \\\"/usr/bin/python3.14 -I -S -B /home/qq/hia-rewrite-20261113-e26e-r1/audit_varint_native_r2_failure_r1.py\\\"\\n    ],\\n    \\\"created_unix_ms\\\": 1794549767053,\\n    \\\"cwd\\\": \\\"/home/qq/hia-rewrite-20261113-e26e-r1\\\",\\n    \\\"env_keys\\\": [],\\n    \\\"executable\\\": \\\"/bin/sh\\\",\\n    \\\"execution_mode\\\": \\\"operator\\\",\\n    \\\"host\\\": \\\"ai395\\\",\\n    \\\"id\\\": \\\"1a1d3805b8d-392-151\\\",\\n    \\\"idempotency_key\\\": \\\"cold-varint-native-r2-closed-failure-readback-r1\\\",\\n    \\\"launch_error\\\": null,\\n    \\\"launch_state\\\": \\\"launched\\\",\\n    \\\"remote_job_dir\\\": \\\"/home/qq/.local/state/hepta-runtime-mac-worker/jobs/1a1d3805b8d-392-151\\\",\\n    \\\"request_digest\\\": \\\"01722c47b71d8de3f93413176caf12b52c9afca6aade9574923c2eaf2c9043fa\\\",\\n    \\\"request_fingerprint\\\": 104194427909410275,\\n    \\\"ssh_target\\\": \\\"ai395-lan\\\",\\n    \\\"system_jobctl\\\": false,\\n    \\\"unit\\\": \\\"hepta-runtime-job-1a1d3805b8d-392-151\\\"\\n  },\\n  \\\"launch\\\": {\\n    \\\"backend\\\": \\\"systemd\\\",\\n    \\\"launcher_pid\\\": null,\\n    \\\"ok\\\": true,\\n    \\\"unit\\\": \\\"hepta-runtime-job-1a1d3805b8d-392-151\\\"\\n  },\\n  \\\"local_record_pending\\\": false,\\n  \\\"reused\\\": false\\n}\"\n    }\n  ],\n  \"structuredContent\": null,\n  \"isError\": false\n}\n","AUDIT-RUN-STATUS.json":"{\n  \"status\": \"fulfilled\",\n  \"value\": {\n    \"content\": [\n      {\n        \"type\": \"text\",\n        \"text\": \"{\\n  \\\"at_unix_ms\\\": 1794549768554,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 0,\\n  \\\"job_id\\\": \\\"1a1d3805b8d-392-151\\\",\\n  \\\"launch_nonce\\\": \\\"6087b1a29ee7724ef5481fc2f93ec0c9\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 502,\\n      \\\"stored\\\": 502\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"succeeded\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\"\n      }\n    ],\n    \"structuredContent\": null,\n    \"isError\": false\n  }\n}\n","AUDIT-RUN-OUTPUT.json":"{\n  \"status\": \"fulfilled\",\n  \"value\": {\n    \"content\": [\n      {\n        \"type\": \"text\",\n        \"text\": \"{\\n  \\\"audit_recorded\\\": true,\\n  \\\"job_id\\\": \\\"1a1d3805b8d-392-151\\\",\\n  \\\"stderr\\\": {\\n    \\\"bytes_hex\\\": \\\"\\\",\\n    \\\"eof\\\": true,\\n    \\\"next_offset\\\": 0,\\n    \\\"offset\\\": 0,\\n    \\\"size\\\": 0,\\n    \\\"text\\\": \\\"\\\"\\n  },\\n  \\\"stdout\\\": {\\n    \\\"bytes_hex\\\": \\\"7b22636865636b73223a2035303439382c20226572726f7273223a205b5d2c20226f776e65725f636c6f736564223a20747275652c20227265706f7274223a207b226279746573223a2034303430382c20226372633332223a20313536313933303137372c20226769745f626c6f62223a202234333965386635393633373736326365396638663033323166333862303964376365626138386535222c20226964656e74697479223a205b36363330362c2037393630383137312c2033333135322c20313030302c20313030302c20312c2034303430382c20313739343534393736383530333332383131322c20313739343534393736383530333332383131325d2c202270617468223a20222f686f6d652f71712f6869612d726577726974652d32303236313131332d653236652d72312f766172696e742d6e61746976652d72322d696e646570656e64656e742d61756469742d72312f524541444241434b2e6a736f6e222c2022736861323536223a202262666430356435363061643562313235316262643465643966316566346661653532343164663434356534333266383464303436616335373764663966383962227d2c2022737461747573223a2022434c4f5345445f4641494c5552455f4f524947494e414c535f414e445f43415553455f524541444241434b5f50415353227d0a\\\",\\n    \\\"eof\\\": true,\\n    \\\"next_offset\\\": 502,\\n    \\\"offset\\\": 0,\\n    \\\"size\\\": 502,\\n    \\\"text\\\": \\\"{\\\\\\\"checks\\\\\\\": 50498, \\\\\\\"errors\\\\\\\": [], \\\\\\\"owner_closed\\\\\\\": true, \\\\\\\"report\\\\\\\": {\\\\\\\"bytes\\\\\\\": 40408, \\\\\\\"crc32\\\\\\\": 1561930177, \\\\\\\"git_blob\\\\\\\": \\\\\\\"439e8f59637762ce9f8f0321f38b09d7ceba88e5\\\\\\\", \\\\\\\"identity\\\\\\\": [66306, 79608171, 33152, 1000, 1000, 1, 40408, 1794549768503328112, 1794549768503328112], \\\\\\\"path\\\\\\\": \\\\\\\"/home/qq/hia-rewrite-20261113-e26e-r1/varint-native-r2-independent-audit-r1/READBACK.json\\\\\\\", \\\\\\\"sha256\\\\\\\": \\\\\\\"bfd05d560ad5b1251bbd4ed9f1ef4fae5241df445e432f84d046ac577df9f89b\\\\\\\"}, \\\\\\\"status\\\\\\\": \\\\\\\"CLOSED_FAILURE_ORIGINALS_AND_CAUSE_READBACK_PASS\\\\\\\"}\\\\n\\\"\\n  }\\n}\"\n      }\n    ],\n    \"structuredContent\": null,\n    \"isError\": false\n  }\n}\n"}
for name,body in sdk.items():write(PUB/'sdk'/name,body.encode())
auditpin,auditraw=read(AUDIT/'READBACK.json');audit=json.loads(auditraw)
assert auditpin['sha256']=='bfd05d560ad5b1251bbd4ed9f1ef4fae5241df445e432f84d046ac577df9f89b'
assert audit['status']=='CLOSED_FAILURE_ORIGINALS_AND_CAUSE_READBACK_PASS' and audit['errors']==[]
catalogpin,catalograw=read(AUDIT/'ORIGINAL-CATALOG.json');catalog=json.loads(catalograw)
assert catalogpin['sha256']=='5adb515abd2d10b7953078485cbb26fdbb7b860a8a362ca35840690f47c64092'
assert catalog['file_count']==53 and catalog['bytes']==8251139
sources={}
actual_expected={}
for row in catalog['files']:
    name=row['relative_path'];actual_expected[name]=row
    sources['actual/'+name]=ACT/name
found={str(p.relative_to(ACT)) for p in ACT.rglob('*') if p.is_file()}
assert found==set(actual_expected)
roots=['root-varint-clean-launch-r1-INTENT.json','root-varint-native-r2-OWNER-READBACK.json',
       'root-varint-native-r2-HJOB-ACK.json','root-varint-native-r2-HJOB-STATUS.json','root-varint-native-r2-HJOB-OUTPUT.json']
for name in roots:sources['root-originals/'+name]=P/name
for name in ['READBACK.json','ORIGINAL-CATALOG.json']:sources['independent/'+name]=AUDIT/name
sources['independent/audit_varint_native_r2_failure_r1.py']=P/'audit_varint_native_r2_failure_r1.py'
for name in sdk:sources['independent-sdk/'+name]=PUB/'sdk'/name
for name in ['REQUEST.json','LAUNCH.json','FROZEN-READBACK.json']:
    sources['frozen-request/'+name]=ROOT/name
for name in ['clean_exec.py','LAUNCH.json','CORRECTION.json']:
    sources['clean-invocation/'+name]=P/'varint-native-r2-clean-launch-r1'/name
for name in ['root-varint-r2-execution-r1-INTENT.json',
             *['root-varint-r2-launch-failure-r1-'+n for n in ('ACK.json','STATUS.json','PROCESS-READ.json','stdout.log','stderr.log')]]:
    sources['previous-shell-failure/'+name]=P/name
rows=[];archive=io.BytesIO();bodies={}
with tarfile.open(fileobj=archive,mode='w',format=tarfile.PAX_FORMAT) as tar:
    for name,path in sorted(sources.items()):
        pin,raw=read(path);pin['archive_path']=name;rows.append(pin);bodies[name]=raw
        if name.startswith('actual/'):
            w=actual_expected[name.removeprefix('actual/')]
            assert all(pin[k]==w[k] for k in ('bytes','sha256','git_blob','identity'))
        item=tarfile.TarInfo(name);item.size=len(raw)
        item.mode=stat.S_IMODE(pin['identity'][2]);item.uid=pin['identity'][3];item.gid=pin['identity'][4]
        item.mtime=pin['identity'][7]//1000000000
        item.pax_headers={'mtime_ns':str(pin['identity'][7]),'original_identity':json.dumps(pin['identity'],separators=(',',':'))}
        tar.addfile(item,io.BytesIO(raw))
data=archive.getvalue();compressed=gzip.compress(data,compresslevel=9,mtime=0)
write(PUB/'all-originals.tar.gz',compressed)
assert gzip.decompress(read(PUB/'all-originals.tar.gz')[1])==data
seen=set()
with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as tar:
    for member in tar:
        assert member.isreg() and member.name not in seen and member.name in bodies;seen.add(member.name)
        row=next(x for x in rows if x['archive_path']==member.name)
        raw=tar.extractfile(member).read()
        assert raw==bodies[member.name] and sha(raw)==row['sha256'] and git(raw)==row['git_blob']
        assert member.mode==stat.S_IMODE(row['identity'][2]) and member.uid==row['identity'][3] and member.gid==row['identity'][4]
        assert member.pax_headers['mtime_ns']==str(row['identity'][7])
assert seen==set(sources)
for row in rows:
    pin,raw=read(Path(row['source_path']))
    assert all(pin[k]==row[k] for k in ('bytes','sha256','git_blob','identity')) and raw==bodies[row['archive_path']]
payload=PUB/'payload';payload.mkdir(mode=0o700)
parts=[]
for n,start in enumerate(range(0,len(compressed),400000)):
    raw=compressed[start:start+400000];name='archive/part-%04d.b64'%n
    encoded=base64.b64encode(raw)
    pin=write(payload/name,encoded)
    assert base64.b64decode(read(payload/name)[1],validate=True)==raw
    parts.append({'path':name,'raw_bytes':len(raw),'raw_sha256':sha(raw),'encoded_bytes':pin['bytes'],'encoded_sha256':pin['sha256'],'git_blob':pin['git_blob']})
assert b''.join(base64.b64decode(read(payload/r['path'])[1],validate=True) for r in parts)==compressed
manifest={'schema':'hia.sqlite.varint.actual-failure-lossless-archive.v1',
 'status':'ORIGINAL_QUALIFICATION_HOLD_PRESERVED_COMPLETE_READBACK',
 'qualification_replayed':False,'native_methods_started':0,'native_returns':0,
 'actual_original_files':53,'actual_original_bytes':8251139,'file_count':len(rows),'original_bytes':sum(r['bytes'] for r in rows),
 'tar_bytes':len(data),'tar_sha256':sha(data),'compressed_bytes':len(compressed),'compressed_sha256':sha(compressed),
 'parts':parts,'files':rows,'typed_file_metadata_readback':True,'all_source_before_after_identical':True}
write(payload/'ARCHIVE.json',wire(manifest))
write(payload/'READBACK.original.json',auditraw);write(payload/'ORIGINAL-CATALOG.original.json',catalograw)
write(payload/'RESTORE.py',"\"\"\"Recover content from the lossless original archive without running the experiment.\"\"\"\nfrom pathlib import Path\nimport base64,gzip,hashlib,io,json,os,stat,tarfile,sys\nroot=Path(__file__).resolve().parent\nmanifest=json.loads((root/'ARCHIVE.json').read_bytes())\nchunks=[]\nfor row in manifest['parts']:\n    raw=base64.b64decode((root/row['path']).read_bytes(),validate=True)\n    assert len(raw)==row['raw_bytes'] and hashlib.sha256(raw).hexdigest()==row['raw_sha256']\n    chunks.append(raw)\ncompressed=b''.join(chunks)\nassert len(compressed)==manifest['compressed_bytes'] and hashlib.sha256(compressed).hexdigest()==manifest['compressed_sha256']\ndata=gzip.decompress(compressed)\nassert len(data)==manifest['tar_bytes'] and hashlib.sha256(data).hexdigest()==manifest['tar_sha256']\ntarget=Path(sys.argv[1]);target.mkdir(mode=0o700,parents=False,exist_ok=False)\nexpected={r['archive_path']:r for r in manifest['files']}\nseen=set()\nwith tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:\n    for member in archive:\n        assert member.isreg() and member.name in expected and member.name not in seen\n        row=expected[member.name];seen.add(member.name)\n        raw=archive.extractfile(member).read()\n        assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']\n        assert member.mode==stat.S_IMODE(row['identity'][2]) and member.uid==row['identity'][3] and member.gid==row['identity'][4]\n        assert member.pax_headers['mtime_ns']==str(row['identity'][7])\n        path=target/member.name\n        assert '..' not in Path(member.name).parts and not Path(member.name).is_absolute()\n        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)\n        with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())\n        os.chmod(path,member.mode);os.utime(path,ns=(row['identity'][7],row['identity'][7]))\nassert seen==set(expected)\nprint(json.dumps({'status':'RESTORED_CONTENT_MODE_MTIME','files':len(seen),'original_host_inodes_not_recreated':True}))\n".encode())
for rel,path in [
 ('FINAL.original.json',ACT/'FINAL.json'),('OWNER-RETURN.original.json',ACT/'OWNER-RETURN.json'),
 ('lifecycle.original.json',ACT/'lifecycle.json'),('owner-request.original.json',ACT/'lifecycle.json.request.json'),
 ('native-INDEX.partial.original.json',ACT/'native/trace/INDEX.partial.json'),
 ('root-OWNER-READBACK.original.json',P/'root-varint-native-r2-OWNER-READBACK.json'),
 ('audit_actual_failure.py',P/'audit_varint_native_r2_failure_r1.py'),
 ('pack_actual_failure.py',Path(__file__))]:
    write(payload/rel,read(path)[1])
summary={'schema':'hia.sqlite.varint.r2.actual-failure-handoff.v1','status':'CLOSED_FAILURE_FULL_ORIGINALS_DURABLE_PACKAGE',
 'request_commit':'230e6a5ae80ad1725922fd99e49d1ba3069dd2d8','clean_envelope_commit':'b1b927cb217220be24c89f5353945c6eb104d3b7',
 'actual_job':'1a1d3766e71-392-140','owner_seconds':180,'cleanup_seconds':3,'owner_exit_code':1,'ECHILD':True,
 'HIA_compiles_completed':1,'C_compiles_completed':2,'finite_methods_started':0,'native_returns':0,
 'actual_original_files':53,'actual_original_bytes':8251139,'archive_file_count':len(rows),'archive_original_bytes':manifest['original_bytes'],
 'cause':"loaded_file_maps tried Path('/dev/zero (deleted)').resolve(strict=True) before the first finite method.",
 'missing_observation':'No complete original maps body or anonymous VMA address was retained; it is not reconstructed.',
 'unchanged_inputs':{'request_frozen':94,'pure0504_source':1686,'system':4806},
 'qualification_status':'HOLD; this custody/readback does not promote the native result.',
 'next_revision':'Bind only the current NativeHiaJsonImage mapping to actual entry address, length, permissions and complete image bytes; no generic deleted-path waiver.',
 'source8_reexecuted':False,'product_replayed':False,'SQL_database_or_durability_closed':False}
write(payload/'HANDOFF.json',wire(summary))
new=[]
for path in sorted(payload.rglob('*')):
    if not path.is_file():continue
    pin,_=read(path);rel=str(path.relative_to(payload))
    new.append({'path':PREFIX+'/'+rel,'relative_path':rel,'local_path':str(path),'mode':'100644','type':'blob','sha':pin['git_blob'],'sha256':pin['sha256'],'size':pin['bytes']})
plan={'schema':'hia.sqlite.varint.actual-failure-publication.v1','repository':'TrillionniumFoundation/Hepta',
      'parent_commit':'b1b927cb217220be24c89f5353945c6eb104d3b7','parent_tree':'50b1ae3412712f45b4db9092428bdbd210fc72ed',
      'prefix':PREFIX,'files':new,'archive':{k:manifest[k] for k in ('file_count','original_bytes','compressed_bytes','compressed_sha256')},
      'status':'LOCAL_FULL_READBACK_ONLY_NOT_YET_GIT_PUBLISHED','new_product_execution':False}
write(PUB/'PLAN.json',wire(plan))
print(json.dumps({'status':plan['status'],'payload_files':len(new),'payload_bytes':sum(r['size'] for r in new),
                 'archive':plan['archive'],'plan_sha256':sha(wire(plan))},sort_keys=True))
