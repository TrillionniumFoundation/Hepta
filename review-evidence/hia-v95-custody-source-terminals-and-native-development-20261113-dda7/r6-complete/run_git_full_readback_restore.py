"""Reconstruct the fixed R6 logical evidence solely from complete Git GET copies."""
from pathlib import Path
import hashlib,json,stat,subprocess,sys,time
ROOT=Path(__file__).resolve().parent
def identity(b):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(path,value):
 with path.open('x',encoding='utf-8') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def main():
 output=ROOT/'git-full-readback-restore-r1';output.mkdir();target=output/'restored'
 transport=json.loads((ROOT/'TRANSPORT.json').read_bytes())
 manifest_raw=(ROOT/'MANIFEST.json').read_bytes()
 assert identity(manifest_raw)=={k:transport['manifest'][k] for k in ('bytes','sha256','git_blob')}
 manifest=json.loads(manifest_raw)
 argv=[sys.executable,'-B',str(ROOT/'restore.py'),str(ROOT/'TRANSPORT.json'),
       str(ROOT/'EXTRA-MEMBERS.json'),str(ROOT/'GIT-CUSTODY/readback'),str(target)]
 write(output/'REQUEST.json',{'argv':argv,'cwd':str(ROOT),'product_execution':False,'extra_git_posts':0,
                             'logical_member_count':10060,'raw_chunk_count':434})
 begun=time.monotonic_ns()
 result=subprocess.run(argv,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
 elapsed=time.monotonic_ns()-begun
 for name,raw in [('stdout',result.stdout),('stderr',result.stderr)]:
  with (output/name).open('xb') as f:f.write(raw)
 report={'schema':'hepta.custody.full-get-actual-restore.v1','returncode':result.returncode,'elapsed_ns':elapsed,
         'stdout':identity(result.stdout),'stderr':identity(result.stderr),
         'transport':identity((ROOT/'TRANSPORT.json').read_bytes()),
         'source_tree':'78155bac080168d2946116ede1607e48b221ec1b',
         'new_product_execution':False,'whole_native':False}
 if result.returncode==0:
  observed=json.loads(result.stdout);report['observations']=observed
  assert observed['status']=='RESTORED_FULLY' and observed['logical_files']==10060
  assert observed['logical_bytes']==787835354 and observed['all_bytes_sha256_git_and_modes_verified'] is True
  assert observed['complete_gzip_crc_isize'] is True
  for name,row in manifest['directories'].items():
   info=(target/name).lstat()
   assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode)==int(row['mode'],8),name
  actual_dirs={p.relative_to(target).as_posix() for p in target.rglob('*') if stat.S_ISDIR(p.lstat().st_mode)}
  actual_members={p.relative_to(target).as_posix() for p in target.rglob('*') if not stat.S_ISDIR(p.lstat().st_mode)}
  assert actual_dirs==set(manifest['directories'])
  assert actual_members==set(manifest['logical_files'])
  report['exact_directory_and_member_sets_verified']=True
  report['all_directory_modes_independently_verified']=True
  report['status']='ALL_FIXED_R6_GIT_GET_ORIGINALS_RESTORED'
 else:report['status']='RESTORE_FAILED'
 write(output/'REPORT.json',report);print(json.dumps(report,sort_keys=True))
 return 0 if report['status']=='ALL_FIXED_R6_GIT_GET_ORIGINALS_RESTORED' else 1
if __name__=='__main__':raise SystemExit(main())
