"""Complete immutable op13 data custody; stdlib only, zero products/CI."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import time
import traceback

ROOT=Path(__file__).resolve().parent
KEYS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
ROOTS={k:Path(v) for k,v in {'r3_actual': '/tmp/hia-op13-execution-r3-dda7/attempt-r1', 'r3_preparation_outer': '/tmp/hia-op13-preparation-outer-r3-dda7', 'r3_product_outer': '/tmp/hia-op13-product-outer-r3-dda7', 'r3_binding_reader': '/tmp/hia-op13-binding-readback-actual-r4-dda7', 'r3_terminal_reader': '/tmp/hia-op13-terminal-readback-actual-r3-dda7', 'r4_binding_reader_author': '/tmp/hia-op13-binding-readback-draft-r4-dda7', 'r3_terminal_reader_author': '/tmp/hia-op13-terminal-reader-draft-r3-dda7', 'r3_admission': '/tmp/hia-progress-v149-20261114-dda7/op13-preparation-admission-r3'}.items()}
EXTRAS={k:Path(v) for k,v in {'binding-r3/BINDING-RESULT.json': '/tmp/hia-op13-execution-r3-dda7/BINDING-RESULT.json', 'binding-r3/BOUND-PLAN.json': '/tmp/hia-op13-execution-r3-dda7/BOUND-PLAN.json', 'binding-r3/COPIES.json': '/tmp/hia-op13-execution-r3-dda7/COPIES.json', 'binding-r3/COPY-ROWS.jsonl': '/tmp/hia-op13-execution-r3-dda7/COPY-ROWS.jsonl', 'binding-r3/SOURCE-MAP.json': '/tmp/hia-op13-execution-r3-dda7/SOURCE-MAP.json', 'binding-r3/SOURCE-STATE.json': '/tmp/hia-op13-execution-r3-dda7/SOURCE-STATE.json', 'root/build_op13_custody_r3.py': '/tmp/hia-progress-v149-20261114-dda7/build_op13_custody_r3.py', 'root/OP13-R3-TERMINAL-READER-RETURN.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-TERMINAL-READER-RETURN.json', 'root/OP13-R3-TERMINAL-READER-EXEC.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-TERMINAL-READER-EXEC.json', 'root/launch_op13_terminal_reader_r3.py': '/tmp/hia-progress-v149-20261114-dda7/launch_op13_terminal_reader_r3.py', 'root/OP13-R3-ACTUAL-TOOL-RETURNS.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-ACTUAL-TOOL-RETURNS.json', 'root/author_op13_terminal_reader_r3.py': '/tmp/hia-progress-v149-20261114-dda7/author_op13_terminal_reader_r3.py', 'root/OP13-R3-OBSERVED-TERMINAL.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-OBSERVED-TERMINAL.json', 'root/observe_op13_r3.py': '/tmp/hia-progress-v149-20261114-dda7/observe_op13_r3.py', 'root/OP13-R3-PRODUCT-RETURN.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-PRODUCT-RETURN.json', 'root/OP13-R3-PRODUCT-EXEC.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-PRODUCT-EXEC.json', 'root/OP13-R3-AUTHOR-ROOT-FULL-GET.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-AUTHOR-ROOT-FULL-GET.json', 'root/OP13-R3-AUTHOR-CUSTODY-RECIPE.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-AUTHOR-CUSTODY-RECIPE.json', 'root/OP13-PRODUCT-AUTHORIZATION-R3.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-PRODUCT-AUTHORIZATION-R3.json', 'root/OP13-PRODUCT-INVOCATION-R3.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-PRODUCT-INVOCATION-R3.json', 'root/OP13-PRODUCT-LAUNCH-R3.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-PRODUCT-LAUNCH-R3.json', 'root/OP13-PRODUCT-BINDER-R3-INVERSE.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-PRODUCT-BINDER-R3-INVERSE.json', 'root/bind_op13_product_launch_r3.py': '/tmp/hia-progress-v149-20261114-dda7/bind_op13_product_launch_r3.py', 'root/author_op13_product_binder_r3.py': '/tmp/hia-progress-v149-20261114-dda7/author_op13_product_binder_r3.py', 'root/OP13-R3-BINDING-READER-RETURN.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-BINDING-READER-RETURN.json', 'root/OP13-R3-BINDING-READER-EXEC.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-BINDING-READER-EXEC.json', 'root/author_op13_binding_reader_r4.py': '/tmp/hia-progress-v149-20261114-dda7/author_op13_binding_reader_r4.py', 'root/OP13-R3-BINDER-RETURN.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-BINDER-RETURN.json', 'root/OP13-R3-BINDER-EXEC.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-BINDER-EXEC.json', 'root/OP13-R3-ADMISSION-RETURN.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-ADMISSION-RETURN.json', 'root/OP13-PREPARATION-AUTHORIZATION-R3.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-PREPARATION-AUTHORIZATION-R3.json', 'root/OP13-R3-ADMISSION-EXEC.json': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-ADMISSION-EXEC.json', 'root/admit_op13_preparation_r3.py': '/tmp/hia-progress-v149-20261114-dda7/admit_op13_preparation_r3.py', 'root/build_op13_admission_r3.py': '/tmp/hia-progress-v149-20261114-dda7/build_op13_admission_r3.py', 'root/OP13-R3-REVIEW-PREFIX.txt': '/tmp/hia-progress-v149-20261114-dda7/OP13-R3-REVIEW-PREFIX.txt'}.items()}

def need(ok,msg):
 if not ok: raise AssertionError(msg)

def stamp(p):return [getattr(Path(p).lstat(),k) for k in KEYS]

def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
 'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}

def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def dump(p,v):
 with Path(p).open('xb') as f:f.write(encoded(v))

def read(p):
 p=Path(p);s=p.lstat();a=stamp(p)
 need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'non-single-link regular input: '+str(p))
 for parent in p.parents:need(stat.S_ISDIR(parent.lstat().st_mode),'parent link or special')
 fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  need([getattr(os.fstat(fd),k) for k in KEYS]==a,'opened inode differs')
  with os.fdopen(fd,'rb',closefd=False) as stream:b=stream.read(s.st_size+1)
  need(len(b)==s.st_size and [getattr(os.fstat(fd),k) for k in KEYS]==a==stamp(p),'input changed during read')
 finally:os.close(fd)
 return b,stat.S_IMODE(s.st_mode),a

def inventory():
 files={};dirs={}
 for label,root in ROOTS.items():
  need(stat.S_ISDIR(root.lstat().st_mode),'missing input root')
  for here,ds,ns in os.walk(root,followlinks=False):
   ds.sort();ns.sort();here=Path(here)
   need(stat.S_ISDIR(here.lstat().st_mode),'directory symlink')
   dirs[label+'/'+here.relative_to(root).as_posix()]=stamp(here)
   for d in ds:need(stat.S_ISDIR((here/d).lstat().st_mode),'directory symlink')
   for n in ns:files[label+'/'+(here/n).relative_to(root).as_posix()]=str(here/n)
 for name,p in EXTRAS.items():files['root_author/'+name]=str(p)
 return files,dirs

def secret_check(name,b):
 if not name.endswith(('.json','.jsonl','.py','.md','.txt','.log','.diff')):return
 need(not re.search(rb'(?i)authorization\s*:\s*(bearer|basic)\s+[A-Za-z0-9+/_.=-]+',b),'credential-bearing authorization')
 need(not re.search(rb'(?i)set-cookie\s*:',b),'credential-bearing cookie header')
 need(not re.search(rb'https?://[^\s"<>]+[?&](?:sig|X-Amz-Signature|X-Goog-Signature)=',b),'signed access URL')

def main():
 start=time.monotonic_ns();files,dirs=inventory();before={n:stamp(p) for n,p in files.items()}
 v=os.statvfs(ROOT);free=v.f_bavail*v.f_frsize
 need(free>=268435456,'custody requires 256MiB available before writing archive')
 dump(ROOT/'INTENT.json',{'schema':'hepta.op13.actual.complete-custody.intent.v1','all_original_files':files,
  'before_seven_stats':before,'directories':dirs,'products':0,'CI':0,'archive_only_no_unpacked_copy':True,
  'raw_preserved':True,'maximum_compressed_bytes':268435456,'minimum_reserved_free_bytes':134217728,
  'actual_qualification':'FAIL','failed_group':'native-11','failed_VM':None,
  'all_success_and_failed_partial_frames_included':True,'scope_excludes_original_input_payload_duplicates':True})
 rows={};unique={};aliases={}
 for name,p in files.items():
  raw,mode,s=read(p);need(s==before[name],'input changed before custody');secret_check(name,raw)
  ident=pin(raw);sha=ident['sha256'];row={'source_path':p,'identity':ident,'mode':mode,'seven_stats':s,
    'storage_path':'objects/'+sha}
  rows[name]=row;aliases.setdefault(sha,[]).append(name)
  if sha not in unique:unique[sha]={'identity':ident,'source_path':p}
  else:need(unique[sha]['identity']==ident,'CAS length/Git collision')
 product=[r for n,r in rows.items() if n.startswith(('r3_actual/','r3_product_outer/'))]
 need(len(product)==40934 and sum(r['identity']['bytes'] for r in product)==64755547,'op13 actual originals changed')
 manifest={'schema':'hepta.op13.actual.complete-custody.manifest.v1','payload_boundaries':{'binding_source_files_per_copy': 3210, 'source_tree': 'f826632c845631ba84d450c3632e94d5b04b2306', 'source_payload_duplicate_in_this_archive': False, 'all_actual_bindings_and_copy_rows_included': True, 'r3_author_recipe': 'ac49bfbeb376e09c5eab56dc0ee6615578340e7e', 'fixture_recipe': 'f6b7a176d43883a1cd71f83ed0fa01f9b5ed6bd2', 'all_compilation_and_Native_raw_included': True, 'compile_full_workspace_observed': False, 'all_frames_retired': False, 'product_status': 'FAIL', 'product_failure': 'native-11', 'reader_status': 'PASS_FAILURE_EVIDENCE_VERIFIED'},'files':rows,'directories':dirs,
  'file_count':len(rows),'logical_bytes':sum(r['identity']['bytes'] for r in rows.values()),
  'objects':unique,'unique_objects':len(unique),'unique_bytes':sum(r['identity']['bytes'] for r in unique.values()),
  'archive_storage_modes_are_transport_only':True,'all_original_modes_are_explicit_per_logical_file':True,
  'original_qualification':'FAIL','whole_native':False,'products':0,'signed_transport_credentials_included':False}
 mb=encoded(manifest)
 with (ROOT/'MANIFEST.json').open('xb') as f:f.write(mb)
 archive=ROOT/'COMPLETE-ORIGINALS.tar.gz'
 with archive.open('xb') as wire:
  with gzip.GzipFile(filename='',mode='wb',fileobj=wire,compresslevel=1,mtime=0) as gz:
   with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
    def add(name,raw):
     t=tarfile.TarInfo(name);t.size=len(raw);t.mode=0o444;t.uid=t.gid=0;t.mtime=0;t.uname=t.gname=''
     tar.addfile(t,io.BytesIO(raw))
    add('MANIFEST.json',mb)
    for sha,row in sorted(unique.items()):
     raw,mode,s=read(row['source_path']);need(pin(raw)==row['identity'],'CAS source changed')
     add('objects/'+sha,raw)
     need(wire.tell()<=268435456,'compressed custody exceeds explicit cap; partial retained')
     v=os.statvfs(ROOT);need(v.f_bavail*v.f_frsize>=134217728,'custody reserve depleted; partial retained')
 ab,_,_=read(archive);archive_pin=pin(ab);del ab
 seen=[];compared=0
 with gzip.open(archive,'rb') as gz:
  with tarfile.open(fileobj=gz,mode='r|') as tar:
   for member in tar:
    need(member.isfile() and not member.issym() and not member.islnk() and member.mode==0o444,
         'invalid transport member')
    need(member.name not in seen,'duplicate transport path');seen.append(member.name)
    stream=tar.extractfile(member);raw=stream.read(member.size+1)
    need(len(raw)==member.size,'truncated transport member')
    if member.name=='MANIFEST.json':need(raw==mb,'manifest transport differs');continue
    need(member.name.startswith('objects/'),'unexpected transport member')
    sha=member.name[8:];need(sha in unique and pin(raw)==unique[sha]['identity'],'transport object differs')
    for logical in aliases[sha]:
     wanted=rows[logical];actual,mode,s=read(wanted['source_path'])
     need(actual==raw and mode==wanted['mode'] and s==wanted['seven_stats'],'full logical restoration differs')
     compared+=1
  while gz.read(1048576):pass
 need(len(seen)==len(unique)+1 and compared==len(rows),'complete transport/readback denominator differs')
 after_files,after_dirs=inventory();need(after_files==files and after_dirs==dirs,'original raw pathset changed')
 need({n:stamp(p) for n,p in files.items()}==before,'original stats changed')
 report={'schema':'hepta.op13.actual.complete-custody.local-readback.v1','status':'PASS_COMPLETE_ORIGINAL_BYTES_AND_MODES',
  'original_qualification':'FAIL','all_actual_raw_files':40934,'all_actual_raw_bytes':64755547,
  'all_files':len(rows),'logical_bytes':manifest['logical_bytes'],'unique_objects':len(unique),'unique_bytes':manifest['unique_bytes'],
  'archive':archive_pin,'manifest':pin(mb),'archive_members':len(seen),'complete_gzip_footer_CRC':True,
  'logical_files_full_byte_compared':compared,'all_original_seven_stats_unchanged':True,'pathsets_unchanged':True,
  'native_calls':8986,'semantic_VM_calls':0,'test_failure':'native-11','later_one_Native_group_not_started':True,
  'product_executions':0,'CI':0,'Git_archive_persistence':'PENDING_SEPARATE_TRANSPORT',
  'signed_access_credentials_included':False,'additional_full_uncompressed_copy_created':False,
  'elapsed_ns':time.monotonic_ns()-start}
 dump(ROOT/'REPORT.json',report);print(json.dumps(report,sort_keys=True))

if __name__=='__main__':
 try:main()
 except BaseException:
  dump(ROOT/'FAILURE.json',{'status':'FAIL_CUSTODY','products':0,'original_product_FAIL_unchanged':True,
       'traceback':traceback.format_exc(),'partial_files_retained':True})
  raise
