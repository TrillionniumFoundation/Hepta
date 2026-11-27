from pathlib import Path
import os,stat,json,hashlib,tarfile,io,time,subprocess
R=Path('/home/qian-qi/hia-artifact-page-current-native-20261127-2ac5')
O=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-artifact-page-current-native-20261127-2ac5/closed-native-components-v1')
O.mkdir(parents=True,mode=0o700)
assert not any(O.iterdir())
stamp_fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_size','st_mtime_ns','st_ctime_ns')
def stamp(st):return [getattr(st,k) for k in stamp_fields]
def readpin(p):
 fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode),p
  h=hashlib.sha256();n=0
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk);n+=len(chunk)
  b=os.fstat(f.fileno())
 assert stamp(a)==stamp(b) and n==a.st_size,p
 return {'bytes':n,'sha256':h.hexdigest(),'mode':stat.S_IMODE(a.st_mode),'stat':stamp(a)}
paths=[]
for top in sorted(R.iterdir()):
 if top.name=='source':continue
 paths.append(top)
 if top.is_dir() and not top.is_symlink():
  paths.extend(sorted(top.rglob('*')))
rows=[];objects={};total=0
for p in paths:
 s=p.lstat();row={'path':p.relative_to(R).as_posix(),'physical_path':str(p),'mode':stat.S_IMODE(s.st_mode)}
 if stat.S_ISDIR(s.st_mode):row['type']='directory'
 elif stat.S_ISLNK(s.st_mode):row.update(type='symlink',target=os.readlink(p))
 else:
  assert stat.S_ISREG(s.st_mode),p
  row.update(type='file',**readpin(p));objects.setdefault(row['sha256'],p);total+=row['bytes']
 rows.append(row)
deps={'B3.flat':'/home/qian-qi/hia-native-current-future-20261127-2ac5/chain-v2/cold/qualification/base/B3.flat'}
depot=Path('/home/qian-qi/hia-native-current-future-20261127-2ac5/chain-v2/depot/201fd124d0c6fc80cb9ad97816e4f69cbc1ea669462b3f86d168566f57817f7e')
for n in ('hia-source-build','hia-agent-store','hia-artifact','hia-agent-artifact-capture','hia-agent-store-init'):deps[n]=str(depot/n)
for n,s in deps.items():
 p=Path(s);row={'path':'__external_captured_inputs/'+n,'physical_path':s,'type':'file',**readpin(p)}
 objects.setdefault(row['sha256'],p);total+=row['bytes'];rows.append(row)
source_head=subprocess.check_output(['git','-C',str(R/'source'),'rev-parse','HEAD']).decode().strip()
source_status=subprocess.check_output(['git','-C',str(R/'source'),'status','--porcelain']).decode()
assert source_head=='3943b381ab6da9d53fe3c9bae15246a52ff338a6' and not source_status
manifest={'schema':'hepta.hia.artifact-page-native-raw-cas.v1','source_current_head':source_head,'source_current_clean':True,
 'scope':'All existing physical v1-v4 native component outputs, drivers, complete materialization inventories, transfer packs and exact external DEV inputs. No transient bytes are invented. Source Git trees are referenced by their preserved commits.',
 'source_commits':['2daf037522fd365e0cc2a151db564a4d207f3635','85ad24d1d3a139e8190a9a1737ed8b74583b6ed0','3943b381ab6da9d53fe3c9bae15246a52ff338a6'],
 'matching_cold_qualified':False,'whole_release_qualified':False,'member_count':len(rows),'file_count':sum(x['type']=='file' for x in rows),
 'physical_file_bytes':total,'unique_blob_count':len(objects),'members':rows}
raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();(O/'manifest.json').write_bytes(raw)
print(json.dumps({'phase':'inventory','members':len(rows),'files':manifest['file_count'],'physical_bytes':total,'unique_blobs':len(objects)}),flush=True)
tmp=O/'complete-native-components.tar.gz.partial';final=O/'complete-native-components.tar.gz'
with tarfile.open(tmp,'w:gz',compresslevel=6) as tar:
 info=tarfile.TarInfo('manifest.json');info.size=len(raw);info.mode=0o400;info.mtime=0;tar.addfile(info,io.BytesIO(raw))
 for key,p in sorted(objects.items()):
  expected=next(x for x in rows if x.get('sha256')==key)
  fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
  with os.fdopen(fd,'rb') as f:
   a=os.fstat(f.fileno());assert stamp(a)==expected['stat'],p
   info=tarfile.TarInfo('blobs/'+key);info.size=a.st_size;info.mode=0o400;info.mtime=0;tar.addfile(info,f)
   assert stamp(os.fstat(f.fileno()))==expected['stat'],p
def verify(path):
 seen={};mraw=None
 with tarfile.open(path,'r:gz') as tar:
  for member in tar:
   assert member.isfile() and member.name not in seen and member.mode==0o400,member.name
   data=tar.extractfile(member);h=hashlib.sha256();size=0;buf=[]
   for chunk in iter(lambda:data.read(1<<20),b''):
    h.update(chunk);size+=len(chunk)
    if member.name=='manifest.json':buf.append(chunk)
   assert size==member.size
   seen[member.name]={'bytes':size,'sha256':h.hexdigest()}
   if member.name=='manifest.json':mraw=b''.join(buf)
 assert mraw==raw
 assert set(seen)=={'manifest.json',*('blobs/'+k for k in objects)}
 for row in rows:
  if row['type']=='file':assert seen['blobs/'+row['sha256']]=={'bytes':row['bytes'],'sha256':row['sha256']}
 return seen
verify(tmp);os.replace(tmp,final)
for row in rows:
 p=Path(row['physical_path'])
 if row['type']=='file':assert readpin(p)=={k:row[k] for k in ('bytes','sha256','mode','stat')},p
 elif row['type']=='symlink':assert p.is_symlink() and os.readlink(p)==row['target']
 else:assert p.is_dir() and stat.S_IMODE(p.stat().st_mode)==row['mode']
assert subprocess.check_output(['git','-C',str(R/'source'),'status','--porcelain'])==b''
result={'schema':'hepta.hia.artifact-page-native-raw-cas-verification.v1','success':True,'source_before_after_equal':True,
 'archive_path':str(final),'archive':readpin(final),'manifest':{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
 'members':len(rows),'files':manifest['file_count'],'physical_file_bytes':total,'unique_blobs':len(objects),'all_blobs_and_logical_members_verified':True,'deleted_originals':False}
(O/'verification.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps(result,sort_keys=True),flush=True)
