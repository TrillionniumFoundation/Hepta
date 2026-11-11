"""Seal the completed shared fixture while its native tests continue."""
from hashlib import sha256
import json
from pathlib import Path
import stat, tarfile, time
source=Path('/dev/shm/hia-v64-native-attempt1/fixture')
output=Path('/workspace/scratch/9acdfa9f5639/hia-v64-integration-development')
archive=output/'native-attempt1-bootstrap-originals.tar.xz'
started=time.monotonic()
while True:
 try:
  raw=(source/'custody.json').read_bytes()
  index=json.loads(raw)
  assert index['status']=='COMPLETE_BYTE_READBACK'
  break
 except (FileNotFoundError,json.JSONDecodeError):
  failure=source/'failure-custody.json'
  if failure.exists():raise RuntimeError('shared fixture failed; preserve raw failure separately')
  if time.monotonic()-started>1200:raise TimeoutError('complete fixture evidence did not appear')
  time.sleep(1)
for row in index['files']:
 p=source/row['path'];data=p.read_bytes()
 assert len(data)==row['bytes'] and sha256(data).hexdigest()==row['sha256']
 assert stat.S_IMODE(p.stat().st_mode)==row['mode']
paths=sorted(p for p in source.rglob('*') if p.is_file())
assert not archive.exists()
with tarfile.open(archive,'w:xz',preset=3) as tar:
 for p in paths:tar.add(p,arcname=p.relative_to(source).as_posix(),recursive=False)
records=[]
with tarfile.open(archive,'r:xz') as tar:
 assert len(tar.getmembers())==len(paths)
 for member in tar:
  data=tar.extractfile(member).read();original=(source/member.name).read_bytes()
  assert data==original and member.mode==stat.S_IMODE((source/member.name).stat().st_mode)
  records.append({'path':member.name,'bytes':len(data),'sha256':sha256(data).hexdigest(),'mode':member.mode})
value={'schema':'hepta.hia.v64-live-bootstrap-original-custody.v1','scope':index['scope'],'status':'ARCHIVE_BYTE_HASH_MODE_READBACK','test_result_not_yet_known':True,'whole_stack_qualification':False,'archive':str(archive),'archive_bytes':archive.stat().st_size,'archive_sha256':sha256(archive.read_bytes()).hexdigest(),'members':len(records),'raw_bytes':sum(r['bytes'] for r in records),'files':records}
(output/'native-attempt1-bootstrap-custody.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:value[k] for k in ('archive','archive_bytes','archive_sha256','members','raw_bytes','scope')}),flush=True)
