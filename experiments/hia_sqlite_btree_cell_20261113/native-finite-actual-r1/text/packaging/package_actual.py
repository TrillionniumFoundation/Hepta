"""Lossless closed B-tree native originals; archive-only, no product or qualification invocation."""
from pathlib import Path
import base64,gzip,hashlib,io,json,os,stat,tarfile
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
ROOT=P/'sqlite-btree-cell-native-r1';ACT=P/'sqlite-btree-cell-native-r1-actual'
OUT=P/'sqlite-btree-cell-native-r1-actual-publication-r1'
PARENT='9156b42e028e95ce060a6738131ee523c7abde48'
def sha(b):return hashlib.sha256(b).hexdigest()
def blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 p=Path(p);s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('regular single-link original')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  if ident(os.fstat(f.fileno()))!=ident(s):raise ValueError('opened identity')
  b=f.read()
  if ident(os.fstat(f.fileno()))!=ident(s):raise ValueError('held original identity')
 if ident(p.lstat())!=ident(s) or len(b)!=s.st_size:raise ValueError('named original identity')
 return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'git_blob':blob(b),'identity':ident(s)}
def put(p,b):
 p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 rb,pin=read(p)
 if rb!=b:raise ValueError('writeback')
 return pin
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def main():
 audit_path=P/'sqlite-btree-cell-native-r1-independent-audit-r2/READBACK.json'
 audit_raw,audit_pin=read(audit_path)
 if audit_pin['bytes']!=305616 or audit_pin['sha256']!='a026202a87e63a7035f90331e18b9e8c7fa309e145ea8d70c3fb890c2b56f3d5':raise ValueError('exact full independent read')
 audit=json.loads(audit_raw)
 if audit['status']!='INDEPENDENT_FULL_BTREE_CELL_NATIVE_TWELVE_339_AND_TWO_C_READBACK_PASS' or audit['errors'] or not audit['owner_closed_before_child_enumeration']:raise ValueError('independent closed finite result')
 life_raw,life_pin=read(ACT/'lifecycle.json');life=json.loads(life_raw);c=life['cleanup']
 if life_pin!=audit['owner']['lifecycle'] or not(c['complete'] and c['observed_echild'] and c['leader_reaped']) or c['remaining_direct_children'] or c['errors'] or c['deadline_exceeded'] or life['returncode']!=0 or life['timed_out']:raise ValueError('exact actual remains closed')
 if OUT.exists():raise ValueError('create-only new publication')
 OUT.mkdir(mode=0o700)
 originals={};typed={}
 expected={r['relative_path']:r for r in audit['actual_originals']['files']}
 actual_names=set()
 for base,dirs,names in os.walk(ACT,followlinks=False):
  directory=Path(base);s=directory.lstat();rel='actual/'+str(directory.relative_to(ACT))
  if rel.endswith('/.'):rel=rel[:-2]
  if not stat.S_ISDIR(s.st_mode):raise ValueError('actual special directory')
  typed[rel]={'name':rel,'kind':'directory','mode':stat.S_IMODE(s.st_mode),'identity':ident(s),'original_path':str(directory)}
  for d in dirs:
   if not stat.S_ISDIR((directory/d).lstat().st_mode):raise ValueError('directory link')
  for name in sorted(names):
   p=directory/name;r=str(p.relative_to(ACT));b,pin=read(p)
   if r not in expected or {'relative_path':r,**pin}!=expected[r]:raise ValueError('original actual changed '+r)
   originals['actual/'+r]=(b,pin);actual_names.add(r)
 if actual_names!=set(expected) or len(actual_names)!=80:raise ValueError('whole actual namespace')
 extras={
  'root-proof/INTENT.original.json':P/'root-btree-cell-native-two-c-r1-INTENT.json',
  'root-proof/OWNER-READBACK.original.json':P/'root-btree-cell-native-two-c-r1-OWNER-READBACK.json',
  'root-proof/HJOB.original.json':P/'root-btree-cell-native-two-c-r1-HJOB.json',
  'independent/READBACK.json':audit_path,
  'independent/audit_actual_r1.py':P/'audit_btree_native_actual_r1.py',
  'independent/audit_actual_r2.py':P/'audit_btree_native_actual_r2.py',
  'independent/r1-INTENT.json':P/'btree-native-actual-independent-read-r1-INTENT.json',
  'independent/r1-HISTORY.json':P/'btree-native-independent-read-r1-HISTORY.json',
  'independent/r2-INTENT.json':P/'btree-native-actual-independent-read-r2-INTENT.json',
  'independent/r2-HJOB.json':P/'btree-native-independent-read-r2-HJOB.json',
  'reference/Record-actual-reader.original.py':P/'sqlite-record-native-r1-actual-publication-r1/payload/audit_actual.py',
  'request/CANONICAL.original.json':P/'sqlite-btree-cell-native-r1-publication/CANONICAL.json',
  'request/EXECUTE.original.json':ROOT/'EXECUTE.json',
  'request/LAUNCH.original.json':ROOT/'LAUNCH.json',
  'packaging/package_actual.py':Path(__file__),
 }
 for name,path in extras.items():
  b,pin=read(path);originals[name]=(b,pin)
 for name,pin in audit['root_originals'].items():
  if read(P/name)[1]!=pin:raise ValueError('Root fixed original changed')
 for name,(_,pin) in originals.items():
  typed[name]={'name':name,'kind':'regular','bytes':pin['bytes'],'sha256':pin['sha256'],'git_blob_sha1':pin['git_blob'],'mode':stat.S_IMODE(pin['identity'][2]),'original':pin}
 archive=OUT/'native-actual-originals.tar'
 with tarfile.open(archive,'x',format=tarfile.PAX_FORMAT) as tar:
  for name,row in sorted(typed.items()):
   info=tarfile.TarInfo(name);info.mode=row['mode'];info.mtime=0
   if row['kind']=='directory':
    info.type=tarfile.DIRTYPE;info.uid=row['identity'][3];info.gid=row['identity'][4];tar.addfile(info)
   else:
    body,pin=originals[name];info.size=len(body);info.uid=pin['identity'][3];info.gid=pin['identity'][4];tar.addfile(info,io.BytesIO(body))
 compressed=OUT/'native-actual-originals.tar.gz'
 with archive.open('rb') as src,compressed.open('xb') as dst:
  with gzip.GzipFile(filename='',mode='wb',fileobj=dst,mtime=0,compresslevel=6) as gz:
   while True:
    b=src.read(1<<20)
    if not b:break
    gz.write(b)
  dst.flush();os.fsync(dst.fileno())
 packed,gzpin=read(compressed);tarraw,tarpin=read(archive)
 if gzip.decompress(packed)!=tarraw:raise ValueError('complete gzip inverse')
 seen=[]
 with tarfile.open(fileobj=io.BytesIO(tarraw),mode='r:') as tar:
  for item in tar:
   if item.name not in typed or item.name in seen:raise ValueError('typed archive namespace')
   row=typed[item.name]
   if item.mode!=row['mode']:raise ValueError('original mode')
   if row['kind']=='directory':
    if not item.isdir():raise ValueError('directory type')
   else:
    if not item.isfile() or item.size!=row['bytes'] or tar.extractfile(item).read()!=originals[item.name][0]:raise ValueError('complete archive member bytes')
   seen.append(item.name)
 if seen!=sorted(typed):raise ValueError('complete exact archive typed set')
 for name,(body,pin) in originals.items():
  b,p=read(pin['path'])
  if b!=body or p!=pin:raise ValueError('original changed after archive '+name)
 files=[]
 def add(name,b):
  p=put(OUT/name,b);files.append({'path':name,'bytes':p['bytes'],'sha256':p['sha256'],'git_blob_sha1':p['git_blob']});return p
 carriers=[]
 for number,offset in enumerate(range(0,len(packed),196608)):
  body=packed[offset:offset+196608];name='carriers/part-%03d.b64'%number
  pin=add(name,base64.b64encode(body)+b'\n')
  carriers.append({'path':name,'offset':offset,'decoded_bytes':len(body),'decoded_sha256':sha(body),'bytes':pin['bytes'],'sha256':pin['sha256'],'git_blob_sha1':pin['git_blob']})
 mirrors=[]
 for name,(body,pin) in sorted(originals.items()):
  if len(body)>512<<10:continue
  try:body.decode('utf-8')
  except UnicodeDecodeError:continue
  add('text/'+name,body);mirrors.append(name)
 rows=[typed[n] for n in sorted(typed)]
 manifest={'schema':'hia.sqlite.btree.cell.native-actual-lossless-archive.v1','sole_parent':PARENT,
  'status':'COMPLETE_TYPED_ALL_CLOSED_ORIGINAL_BYTES','originals':rows,'regular_count':len(originals),'typed_count':len(typed),
  'original_bytes':sum(len(b) for b,p in originals.values()),'actual_regular_count':80,'actual_regular_bytes':64806368,
  'tar':tarpin,'gzip':gzpin,'carriers':carriers,'mirrored_originals':mirrors,
  'full_gzip_tar_inverse_and_all_originals_after_read':True,'all_actual_files_included':True,
  'request_full_originals_retained_in_parent':PARENT,'shared_1686_source_bytes_retained_in_ancestor':'69a6e96e40499a86db48f76e6d2bc54dd9788d06',
  'native_or_VM_or_C_reexecuted_by_archiver':False}
 add('ARCHIVE-MANIFEST.json',wire(manifest))
 restore="""from pathlib import Path
import base64,gzip,hashlib,io,json,tarfile,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);m=json.loads((root/'ARCHIVE-MANIFEST.json').read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
packed=bytearray()
for row in m['carriers']:
 b=(root/row['path']).read_bytes()
 if len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('whole carrier')
 raw=base64.b64decode(b,validate=False)
 if len(raw)!=row['decoded_bytes'] or sha(raw)!=row['decoded_sha256'] or len(packed)!=row['offset']:raise ValueError('decoded carrier')
 packed.extend(raw)
if len(packed)!=m['gzip']['bytes'] or sha(packed)!=m['gzip']['sha256']:raise ValueError('whole gzip')
raw=gzip.decompress(packed)
if len(raw)!=m['tar']['bytes'] or sha(raw)!=m['tar']['sha256']:raise ValueError('whole tar')
expected={r['name']:r for r in m['originals']};seen=set();out.mkdir(mode=0o700,parents=False,exist_ok=False)
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
 for item in tar:
  if item.name not in expected or item.name in seen or item.name.startswith('/') or '..' in Path(item.name).parts:raise ValueError('typed namespace')
  row=expected[item.name];p=out/item.name
  if item.mode!=row['mode']:raise ValueError('original mode')
  if row['kind']=='directory':
   if not item.isdir():raise ValueError('directory type')
   p.mkdir(mode=row['mode'],parents=True,exist_ok=True)
  else:
   if not item.isfile():raise ValueError('regular type')
   b=tar.extractfile(item).read()
   if len(b)!=row['bytes'] or sha(b)!=row['sha256']:raise ValueError('full member')
   p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   with p.open('xb') as f:f.write(b)
   p.chmod(row['mode'])
  seen.add(item.name)
if seen!=set(expected):raise ValueError('missing original')
print(json.dumps({'typed':len(seen),'regular':m['regular_count'],'bytes':m['original_bytes'],'native_reexecuted':False}))
"""
 add('restore_originals.py',restore.encode())
 handoff={'schema':'hia.sqlite.btree.cell.native-actual-publication.v1','status':'FINITE_NATIVE_TWELVE_339_AND_TWO_C_PASS_ONLY',
  'sole_parent':PARENT,'prefix':'experiments/hia_sqlite_btree_cell_20261113/native-finite-actual-r1',
  'root_actual_job':'1a1d44f551e-392-34b','owner_seconds':180,'cleanup_seconds':3,'owner_elapsed_ns':3543490777,
  'worker_elapsed_ns':audit['timings_ns']['worker'],'native_child_elapsed_ns':audit['timings_ns']['native_child'],
  'compile_limits':{'wall_seconds':20,'cpu_seconds':10,'output_bytes':1048576},
  'methods':12,'native_returns':339,'C_calls_each':253,'refusals_not_called_each':86,
  'trace':{'records':678,'bytes':48281463,'sha256':'4341a8b00ff94589cd43a8fbce3608c5f64e992bf1c7b797bb04919c75083891'},
  'HIA_image':{'bytes':65738,'sha256':'658b6024e53ffe0e2661ad670a72b5059158fa26fc57b2c3dac2d3ea623abe3d'},
  'inputs':{'fixed':136,'source':1686,'system':4806},'actual_files':80,'actual_bytes':64806368,
  'independent_readback':audit_pin,'saved_body_checks':12552,'additional_final_writeback_check':1,
  'reader_r1_extra_mode_preflight_HOLD_preserved':True,'originals':len(originals),'original_bytes':manifest['original_bytes'],
  'archive_gzip':gzpin,'scope':'Finite selected-cell native HIA plus complete legal-cell original two-C oracle only; no wholepage/tree, SQL, pager, durability, current matching cold or default activation.',
  'no_qualification_replay':True}
 add('HANDOFF.json',wire(handoff))
 put(OUT/'PUBLISH.json',wire({'schema':'hia.sqlite.btree.cell.native-actual-publication-files.v1','files':files,'all_originals_lossless':True,'qualification_reexecuted':False}))
 print(json.dumps({'output':str(OUT),'status':handoff['status'],'regular':len(originals),'typed':len(typed),'original_bytes':manifest['original_bytes'],'gzip':gzpin,'files':len(files),'carriers':len(carriers),'PUBLISH':read(OUT/'PUBLISH.json')[1]}))
if __name__=='__main__':main()
