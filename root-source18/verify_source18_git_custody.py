import base64,gzip,hashlib,io,json,os,stat,tarfile
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7')
def pin(raw):
 return dict(bytes=len(raw),mode='100644',sha256=hashlib.sha256(raw).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
def seven(s):
 return dict(device=s.st_dev,inode=s.st_ino,nlink=s.st_nlink,mode=s.st_mode,bytes=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
v=json.loads((D/'source18-git-inputs.json').read_bytes())
assert pin(v['recipe_raw'].encode())['git_blob']==v['recipe_git']
recipe=json.loads(v['recipe_raw']);assert len(v['leaves'])==len(recipe['entries'])==20
raws={}
for got,e in zip(v['leaves'],recipe['entries']):
 assert got['entry']==e
 raw=got['raw'].encode();p=pin(raw);assert p['git_blob']==e['sha'] and p['bytes']==e['bytes']
 if 'sha256' in e:assert p['sha256']==e['sha256']
 raws[e['path'].split('/')[-1]]=raw
index=json.loads(raws['PARTS-INDEX.json']);chunks=[]
for i,row in enumerate(index['parts']):
 raw=raws[row['file']];assert pin(raw)==row['pin']
 part=json.loads(raw);chunk=base64.b64decode(part['base64'],validate=True)
 assert part['index']==row['index']==i and part['decoded_offset']==sum(map(len,chunks))
 assert len(chunk)==part['decoded_bytes']==row['decoded_bytes']
 assert hashlib.sha256(chunk).hexdigest()==part['decoded_sha256']==row['decoded_sha256']
 assert part['archive_sha256']==index['archive']['sha256']
 chunks.append(chunk)
archive=b''.join(chunks);assert pin(archive)==index['archive']
decoded=gzip.decompress(archive);cas={}
with tarfile.open(fileobj=io.BytesIO(decoded),mode='r:') as t:
 members=t.getmembers();assert len(members)==44 and len({m.name for m in members})==44
 assert all(m.isfile() and m.mode==0o644 and m.uid==m.gid==m.mtime==0 for m in members)
 assert t.extractfile('MANIFEST.json').read()==raws['MANIFEST.json']
 for m in members:
  if m.name=='MANIFEST.json':continue
  assert m.name.startswith('CAS/') and len(m.name)==68
  raw=t.extractfile(m).read();key=m.name[4:];assert hashlib.sha256(raw).hexdigest()==key and len(raw)==m.size;cas[key]=raw
manifest=json.loads(raws['MANIFEST.json']);assert len(cas)==manifest['unique_blobs']==43
files=dirs=logical=0
for row in manifest['nodes']:
 path=Path(row['source']);before=path.lstat();assert seven(before)==row['stat'],str(path)
 assert stat.S_IMODE(before.st_mode)==row['posix_mode']
 if row['type']=='file':
  assert stat.S_ISREG(before.st_mode);raw=cas[row['pin']['sha256']];assert pin(raw)==row['pin']
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   assert seven(os.fstat(fd))==row['stat']
   with os.fdopen(fd,'rb',closefd=False) as f:current=f.read()
   assert current==raw and seven(os.fstat(fd))==row['stat']
  finally:os.close(fd)
  files+=1;logical+=len(raw)
 elif row['type']=='directory':assert stat.S_ISDIR(before.st_mode);dirs+=1
 else:raise AssertionError('unexpected symlink or special')
 assert seven(path.lstat())==row['stat']
assert (files,dirs,logical)==(54,12,9823915)
assert manifest['files']==files and manifest['directories']==dirs and manifest['logical_bytes']==logical and manifest['symlinks']==0
expected={row['source'] for row in manifest['nodes'] if row['path'].startswith('evidence')}
actual={str(Path(manifest['source_root']))}
for f,ds,fs in os.walk(manifest['source_root'],followlinks=False):actual.update(str(Path(f)/n) for n in ds+fs)
assert actual==expected
report=dict(schema='hepta.root-source18-complete-git-custody-readback.v1',status='PASS_ALL_TWENTY_GIT_LEAVES_AND_ALL_ORIGINAL_BYTES',recipe_git=v['recipe_git'],fresh_full_Git_leaves=20,archive=pin(archive),parts=len(chunks),complete_gzip_CRC=True,tar_members=44,CAS_objects=43,files=files,directories=dirs,logical_bytes=logical,all_file_bytes_pins_modes_seven_stats=True,complete_current_evidence_path_set=True,restored_duplicate_created=False,products_by_reader=0,whole_native=False)
out=D/'ROOT-SOURCE18-GIT-CUSTODY.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(report=str(out),pin=pin(out.read_bytes()),status=report['status'])))
