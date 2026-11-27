from pathlib import Path
import os,stat,json,hashlib,time
R=Path('/tmp/hia-runtime-artifact-recovery-20261114-dda7')
fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def seven(s):return [getattr(s,k) for k in fields]
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
mapbytes=(R/'CURRENT-FILE-MAP.json').read_bytes();mapping=json.loads(mapbytes);root=Path(mapping['root'])
report={'schema':'hepta.runtime-recovery-complete-disk-readback.v1','status':'INCOMPLETE','source_map_pin':pin(mapbytes),'binary_execution':False,'product_calls':0,'checked_files':0,'checked_bytes':0}
started=time.monotonic()
try:
 actual_paths=[];actual_dirs=[]
 for base,ds,fs in os.walk(root,followlinks=False):
  for name in ds:
   p=Path(base)/name;assert stat.S_ISDIR(p.lstat().st_mode) and not p.is_symlink()
   actual_dirs.append(p.relative_to(root).as_posix())
  for name in fs:
   p=Path(base)/name;assert stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink()
   actual_paths.append(p.relative_to(root).as_posix())
 assert set(actual_paths)=={x['path'] for x in mapping['files']}
 assert set(actual_dirs)==set(mapping['new_directories'])
 for row in mapping['files']:
  p=root/row['path'];before=p.lstat();assert seven(before)==row['new_file_seven_stat']
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  with os.fdopen(fd,'rb') as f:
   assert seven(os.fstat(f.fileno()))==row['new_file_seven_stat']
   b=f.read(row['pin']['bytes']+1)
   assert pin(b)==row['pin']
   assert seven(os.fstat(f.fileno()))==row['new_file_seven_stat']
  assert seven(p.lstat())==row['new_file_seven_stat']
  assert stat.S_IMODE(p.lstat().st_mode)==row['mode'] and p.lstat().st_nlink==1
  report['checked_files']+=1;report['checked_bytes']+=len(b)
 assert report['checked_files']==2496 and report['checked_bytes']==108197034
 report['directories_checked']=len(actual_dirs)+1
 report['critical']=[row for row in mapping['files'] if row['path'] in ('bin/python3.14','lib/libpython3.14.so.1.0')]
 report['status']='ALL_CURRENT_FILES_FULL_BYTES_MODES_SEVEN_STATS_PATHSETS_MATCH'
except BaseException as e:
 report['status']='READBACK_FAILED';report['error_type']=type(e).__name__;report['error']=str(e);raise
finally:
 report['elapsed_seconds']=time.monotonic()-started
 (R/'DATA-READBACK.json').open('x').write(json.dumps(report,sort_keys=True,indent=2)+'\n')
 print(json.dumps(report,sort_keys=True))
