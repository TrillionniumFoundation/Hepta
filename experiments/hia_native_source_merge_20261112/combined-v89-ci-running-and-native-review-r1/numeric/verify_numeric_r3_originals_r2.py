"""Independent full read of frozen numeric actual originals; no product execution."""
from pathlib import Path,PurePosixPath
import hashlib,json,stat,tarfile,time
ROOT=Path('/workspace/scratch/e26ed3e2edcf/core-numeric-native-actual-r3')
MANIFEST=ROOT/'ORIGINAL-MANIFEST.json'
manifest_raw=MANIFEST.read_bytes();manifest=json.loads(manifest_raw)
pins={x['path']:x for x in manifest['entries']}
assert len(pins)==len(manifest['entries'])==241
actual_root=Path(manifest['source_root'])
assert actual_root==Path('/tmp/hia-core-compare-native-development-r3')
index_raw=(ROOT/'originals/native/trace/INDEX.json').read_bytes();index=json.loads(index_raw)
chunks=index['chunks'];chunk_by_path={'native/trace/'+x['path']:x for x in chunks}
assert len(chunk_by_path)==len(chunks)==31
assert index['stream_closed'] is True and index['pending_entry'] is None and index['all_cases_complete'] is True
assert index['entry_bytes']==1920 and index['record_bytes']==960 and index['buffer_bytes']==[256,128,512]
archive=ROOT/'ALL-ORIGINALS.tar.xz';started=time.monotonic();seen=[];regular=0;total=0;trace_count=0;trace_bytes=0;trace=hashlib.sha256();rows=[]
with archive.open('rb') as f:archive_sha=hashlib.file_digest(f,'sha256').hexdigest()
assert archive.stat().st_size==11199164 and archive_sha=='811187aa2fc01c1d799c9a0a2b4fadc931e6fb2304cbed48a8a80b2e178dbeaf'
with tarfile.open(archive,'r|xz') as tar:
 for item in tar:
  n=PurePosixPath(item.name);assert not n.is_absolute() and '..' not in n.parts and '\\' not in item.name and item.name in pins and item.name not in seen
  seen.append(item.name);pin=pins[item.name];assert item.mode==pin['mode'] and item.uid==item.gid==0
  p=actual_root/item.name;s=p.lstat();ident={k:getattr(s,'st_'+k) for k in ['dev','ino','mode','nlink','size','mtime_ns','ctime_ns','uid','gid']}
  assert ident==pin['original_identity'],item.name
  if pin['kind']=='directory':assert item.isdir() and stat.S_ISDIR(s.st_mode);continue
  assert pin['kind']=='file' and item.isfile() and stat.S_ISREG(s.st_mode) and item.size==pin['size']
  digest=hashlib.sha256();count=0;is_trace=item.name in chunk_by_path
  if is_trace:
   ch=chunks[trace_count];assert item.name=='native/trace/'+ch['path'] and ch['offset']==trace_bytes and ch['length']<=index['chunk_bound'] and ch['length']%1920==0
  stream=tar.extractfile(item)
  while block:=stream.read(1<<20):
   count+=len(block);digest.update(block)
   if is_trace:trace.update(block);trace_bytes+=len(block)
  assert count==pin['size'] and digest.hexdigest()==pin['sha256'],item.name
  with p.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==pin['sha256'],item.name
  assert {k:getattr(p.lstat(),'st_'+k) for k in ident}==ident
  if is_trace:assert count==ch['length'] and digest.hexdigest()==ch['sha256'];trace_count+=1
  regular+=1;total+=count;rows.append({'path':item.name,'bytes':count,'sha256':digest.hexdigest(),'original_identity_preserved':True,'mode':item.mode})
assert set(seen)==set(pins) and regular==229 and total==290642150
assert trace_count==31 and trace_bytes==index['raw_bytes']==252282240 and trace.hexdigest()==index['raw_sha256']=='f71b1aec2673bc973e27e92cacb0c2f1be3b3dc3945952d39e62412544db2558'
assert index['entry_count']==trace_bytes//1920==131397 and sum(index['status_counts'].values())==131397
offset=0;oracle_pairs=[]
assert len(index['cases'])==185
for i,case in enumerate(index['cases'],1):
 assert case['case_id']==i and case['complete'] is True and case['first_entry']==offset
 offset+=case['entry_count'];metadata=case['metadata']
 if 'VM_pair_index' in metadata:oracle_pairs.append(metadata['VM_pair_index'])
 if 'expected_relation' in metadata:assert case['actual_relation']==metadata['expected_relation']
 if 'expected_predicate' in metadata:assert case['actual_predicate']==metadata['expected_predicate']
assert offset==131397 and oracle_pairs==list(range(172))
report={'schema':'hia.numeric-r3.root-independent-complete-actual-byte-readback.v1','status':'PASS','scope':'Independent whole archive and original byte/mode/identity reads plus trace concatenation and existing recorded case joins; no product reexecution','canonical_commit':'8abaaa8c0dd381b8ab4422d13eee7b4f033f1aea','archive_bytes':11199164,'archive_sha256':archive_sha,'typed_entries':241,'regular_files':regular,'regular_bytes':total,'trace_chunks':trace_count,'trace_bytes':trace_bytes,'trace_sha256':trace.hexdigest(),'entry_count':131397,'cases':185,'original_VM_case_indices':172,'all_existing_case_oracle_fields_match':True,'source_manifest_sha256':hashlib.sha256(manifest_raw).hexdigest(),'trace_index_sha256':hashlib.sha256(index_raw).hexdigest(),'rows':rows,'seconds':time.monotonic()-started,'Core39_18_116_or_cold_or_installed_promoted':False,'whole_native_rewrite':False}
out=Path('/workspace/scratch/e26ed3e2edcf/root/numeric-r3-independent-full-readback.json')
with out.open('x') as f:f.write(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='rows'},sort_keys=True))
