import base64,hashlib,json,stat,zlib
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35');D=R/'v95-audit-mount-r1/v140-progress/storage-complete-Git-readback';S=R/'v132-inspect-machine-entry-r1/successor-r2'
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def load(p):return json.loads(p.read_bytes())
def st(p):
 q=p.lstat();return {'bytes':q.st_size,'ctime_ns':q.st_ctime_ns,'device':q.st_dev,'inode':q.st_ino,'mode':stat.S_IMODE(q.st_mode),'mtime_ns':q.st_mtime_ns,'nlink':q.st_nlink}
parts=load(D/'PARTS.json');man=load(D/'MANIFEST.json');chunks=[];offset=0
for i,row in enumerate(parts['parts']):
 raw=(D/('part-%03d.json'%i)).read_bytes();assert all(pin(raw)[k]==row[k] for k in ['bytes','git_blob','sha256'])
 p=json.loads(raw);b=base64.b64decode(p['data_base64'],validate=True);assert base64.b64encode(b).decode()==p['data_base64']
 assert p['index']==i and p['offset']==row['offset']==offset and pin(b)==p['data_pin']==row['data_pin'];chunks.append(b);offset+=len(b)
raw=b''.join(chunks);assert pin(raw)==parts['capsule']==man['capsule']
assert raw==(S/'storage-retirement-complete-custody-r1/CAPSULE.json').read_bytes()
capsule=json.loads(raw);assert capsule['codec']=='zlib+base64';packed=base64.b64decode(capsule['data'],validate=True)
assert base64.b64encode(packed).decode()==capsule['data']
z=zlib.decompressobj();raw=z.decompress(packed,capsule['payload']['bytes']+1)
assert z.eof and not z.unused_data and not z.unconsumed_tail and pin(raw)==capsule['payload']
payload=json.loads(raw);assert payload['files']==man['files'] and len(payload['files'])==42
objects={}
for sha,value in payload['objects_base64_by_sha256'].items():
 b=base64.b64decode(value,validate=True);assert base64.b64encode(b).decode()==value and pin(b)['sha256']==sha;objects[sha]=b
assert len(objects)==man['unique_objects']==37
for name,row in payload['files'].items():
 assert not name.startswith('/') and all(x not in ['','.','..'] for x in name.split('/'))
 b=objects[row['sha256']];p=S/name;before=st(p);assert stat.S_ISREG(p.lstat().st_mode)
 assert all(pin(b)[k]==row[k] for k in ['bytes','git_blob','sha256']) and before['mode']==row['mode']
 assert before==payload['source_stat_before'][name] and p.read_bytes()==b and st(p)==before
assert sum(row['bytes'] for row in payload['files'].values())==4598950
readback=load(D/'READBACK.json');assert readback['local_original_expanded_files_retired']==486 and readback['retired_logical_bytes']==1031330170
report={'schema':'hepta.root-inspect-storage-custody-readback.v1','status':'PASS_FULL_GIT_PARTS_AND_ALL_ORIGINAL_RECORDS','recipe':'e2d34f306fd89d559ef367ef6b02c89633fd8d95','parts':5,'capsule':man['capsule'],'files':42,'original_bytes':4598950,'unique_objects':37,'all_current_record_bytes_modes_seven_stats_unchanged':True,'local_expanded_original_files_retired':486,'local_expanded_original_bytes_retired':1031330170,'original_archive_70_parts_and_source_runtime_images_failure_scopes_preserved':True,'root_new_deletions':0,'product_executions':0,'whole_native':False}
out=D.parent/'ROOT-INSPECT-STORAGE-COMPLETE-READBACK.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'report':str(out),'identity':pin(out.read_bytes())}))
