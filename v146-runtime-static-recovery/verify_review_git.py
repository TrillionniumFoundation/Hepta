from pathlib import Path
import base64,hashlib,json,stat,zlib
R=Path('/tmp/hia-runtime-artifact-recovery-20261114-dda7');G=R/'git-readback-transport'
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
manifest_bytes=(G/'CAPSULE-MANIFEST.json').read_bytes()
assert pin(manifest_bytes)['git_blob']=='c4940616786c48ee7e318e516fdfcffa87d35429'
m=json.loads(manifest_bytes);chunks=[];position=0
for i,row in enumerate(m['parts']):
 b=(G/Path(row['file']).name).read_bytes();assert pin(b)==row['pin']
 p=json.loads(b);assert p['ordinal']==i and p['count']==5 and p['offset']==position
 raw=base64.b64decode(p['data'],validate=True);assert pin(raw)==p['decoded_pin'];chunks.append(raw);position+=len(raw)
wire=b''.join(chunks);assert pin(wire)==m['zlib_pin']
d=zlib.decompressobj();raw=d.decompress(wire)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail
assert pin(raw)==m['decoded_json_pin'];o=json.loads(raw)
assert len(o['files'])==m['logical_files']==16
seen=[];logical=0
for row,declared in zip(o['files'],m['files']):
 assert {k:row[k] for k in ('file','mode','pin')}==declared
 b=row['content'].encode('utf-8');assert pin(b)==row['pin']
 p=R/row['file'];s=p.lstat();assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==row['mode']
 assert p.read_bytes()==b
 fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 assert all(getattr(p.lstat(),k)==getattr(s,k) for k in fields)
 seen.append(declared);logical+=len(b)
assert logical==m['logical_bytes']
report={'schema':'hepta.runtime-static-recovery.actual-git-readback.v1','status':'ALL_5_ACTUAL_GET_PARTS_AND_16_TEXT_FILES_EXACT','manifest_pin':pin(manifest_bytes),'zlib_pin':pin(wire),'decoded_json_pin':pin(raw),'logical_files':16,'logical_bytes':logical,'files':seen,'binary_payloads_copied':False,'binary_execution':False,'product_calls':0,'old_paths_recreated':False,'runtime_dynamic_qualification':False,'prior_venv_qualification':False,'old_stat_qualification':False}
b=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();(R/'ACTUAL-GIT-READBACK.json').open('xb').write(b)
print(json.dumps({'report_pin':pin(b),'logical_files':16,'logical_bytes':logical},sort_keys=True))
