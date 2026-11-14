"""Custody-only stdin writer. No product imports, execution, network or retries."""
from pathlib import Path
import hashlib,json,os,stat,sys

ROOT=Path('/tmp/hia-op13-actual-transport-r3-dda7')
def pin(raw):
 return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
  'sha256':hashlib.sha256(raw).hexdigest()}
print(json.dumps({'status':'READY','products':0}),flush=True)
for line in sys.stdin:
 try:
  request=json.loads(line)
  if request=={'operation':'stop'}:
   print(json.dumps({'status':'STOPPED','products':0}),flush=True);break
  assert request['operation']=='write'
  path=Path(request['path']);assert path.is_absolute() and ROOT in path.parents
  assert path.relative_to(ROOT).parts[0] in ('actual-get','receipts','tool-envelopes')
  raw=request['content'].encode('utf-8');assert pin(raw)==request['pin']
  path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  for parent in path.parents:assert stat.S_ISDIR(parent.lstat().st_mode)
  try:
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
  except FileExistsError:
   assert stat.S_ISREG(path.lstat().st_mode) and path.lstat().st_nlink==1
   assert path.read_bytes()==raw and stat.S_IMODE(path.lstat().st_mode)==0o644
   written=False
  else:
   with os.fdopen(fd,'wb') as stream:stream.write(raw)
   path.chmod(0o644);written=True
  observed=path.read_bytes();assert observed==raw and pin(observed)==request['pin']
  print(json.dumps({'status':'WRITTEN' if written else 'EXACT_EXISTING_READBACK',
    'path':str(path),'pin':pin(observed),'products':0}),flush=True)
 except BaseException as error:
  print(json.dumps({'status':'FAIL','type':type(error).__name__,'error':str(error),'products':0}),flush=True)
  raise
