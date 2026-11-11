from pathlib import Path
from hashlib import sha256
import json,os,re,stat,tarfile,time,shutil
BASE=Path('/workspace/scratch/9acdfa9f5639');ROOT=BASE/'native-agent-edit-render-next'
OUT=BASE/'hia-batch-r2-published-raw-retirement'
ARCHIVE=BASE/'hia-edit-render-batch-r2-development.tar.xz'
CUSTODY=BASE/'hia-edit-render-batch-r2-development.tar.xz.custody.json'
EXPECTED_ARCHIVE='2b37b276af23a01e9096cfe0bbff24dd786bdae9274261d6b2fe749f97e08be1'
EXPECTED_CUSTODY='09f16d96b2b5247b83b604e17116b7a855f556a0f73cf8f664259b9fc035cf83'
def digest(p):
 h=sha256()
 with p.open('rb') as f:
  while raw:=f.read(1<<20):h.update(raw)
 return h.hexdigest()
start=time.monotonic_ns();assert digest(ARCHIVE)==EXPECTED_ARCHIVE and digest(CUSTODY)==EXPECTED_CUSTODY
meta=json.loads(CUSTODY.read_bytes());rows=meta['members'];lookup={x['path']:i for i,x in enumerate(rows)};assert len(lookup)==len(rows)
allowed={'edit-render-batch-case95-r1','edit-render-batch-differential-r1-attempt1',
 'edit-render-batch-differential-r1-groups','edit-render-batch-smoke-r1','edit-render-batch-smoke-r2',
 'edit-render-batch-protocol-r1','edit-render-batch-protocol-r2','edit-render-batch-large-r2',
 'edit-render-batch-r2-transition-replay','edit-render-batch-private-counterexamples-r1'}
selected=[]
for i,row in enumerate(rows):
 parts=Path(row['path']).parts;p=Path(row['source_path'])
 if len(parts)<4 or parts[0]!='development' or parts[1] not in allowed:continue
 if not any(x in ('raw','buffers') for x in parts[2:-1]):continue
 if not re.fullmatch('[0-9a-f]{64}(?:\\.zlib)?',parts[-1]):continue
 assert p.is_relative_to(ROOT) and p==ROOT/row['path']
 if not p.exists():continue
 st=p.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
 selected.append(i)
selection={'schema':'hepta.hia.published-raw-retirement.v1','authority':'parent explicit completed r11/r12 recovery-only duplicate cleanup',
 'remote_recovery_commit':'2742e2aef9d4f3b4b94049bee4a73af3b9ed90cf','archive':str(ARCHIVE),'archive_sha256':EXPECTED_ARCHIVE,
 'custody':str(CUSTODY),'custody_sha256':EXPECTED_CUSTODY,'member_indices':selected,
 'selected_files':len(selected),'selected_bytes':sum(rows[i]['bytes'] for i in selected),
 'scope':'only completed batch raw/buffers content-addressed objects; no source/images/receipts/harness/ledger/summary/archive/custody removal'}
raw=(json.dumps(selection,sort_keys=True)+'\n').encode();(OUT/'selection.json').write_bytes(raw)
selected_set=set(selected);verified=set();all_archived=0;allbytes=0
with tarfile.open(ARCHIVE,'r|xz') as tar:
 for entry in tar:
  assert entry.isfile() and entry.name in lookup
  i=lookup[entry.name];row=rows[i];assert entry.size==row['bytes'] and entry.mode==row['mode']
  h=sha256();n=0;f=tar.extractfile(entry)
  original=Path(row['source_path']).open('rb') if i in selected_set else None
  try:
   while chunk:=f.read(1<<20):
    h.update(chunk);n+=len(chunk)
    if original is not None:assert original.read(len(chunk))==chunk
   if original is not None:assert original.read(1)==b''
  finally:
   if original is not None:original.close()
  assert n==row['bytes'] and h.hexdigest()==row['sha256'];all_archived+=1;allbytes+=n
  if i in selected_set:
   assert stat.S_IMODE(Path(row['source_path']).lstat().st_mode)==row['mode'];verified.add(i)
assert all_archived==len(rows) and verified==selected_set
validation={'status':'COMPLETE_ARCHIVE_AND_SELECTED_LIVE_BYTES_MODES_MATCH','archive_members':all_archived,'archive_raw_bytes':allbytes,
 'selected_files':len(selected),'selected_bytes':selection['selected_bytes'],'selection_sha256':sha256(raw).hexdigest(),
 'elapsed_ns':time.monotonic_ns()-start}
(OUT/'verified-before-removal.json').write_text(json.dumps(validation,indent=2,sort_keys=True)+'\n')
removed=0;total=0
with (OUT/'removed-member-indices.jsonl').open('x') as ledger:
 for i in selected:
  row=rows[i];p=Path(row['source_path']);before=p.lstat()
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'] and stat.S_IMODE(before.st_mode)==row['mode']
  assert digest(p)==row['sha256']
  after=p.lstat();assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
  p.unlink();removed+=1;total+=row['bytes'];ledger.write(str(i)+'\n')
  if removed%2048==0:ledger.flush()
 ledger.flush();os.fsync(ledger.fileno())
assert removed==len(selected) and total==selection['selected_bytes']
assert digest(ARCHIVE)==EXPECTED_ARCHIVE and digest(CUSTODY)==EXPECTED_CUSTODY
summary={'status':'EXACT_PUBLISHED_RAW_DUPLICATES_REMOVED','removed_files':removed,'removed_bytes':total,
 'archive_and_custody_preserved':True,'no_production_owner_removed':True,'elapsed_ns':time.monotonic_ns()-start,
 'disk_after':dict(zip(('total','used','free'),shutil.disk_usage('/workspace')))}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');print(json.dumps(summary,sort_keys=True),flush=True)
