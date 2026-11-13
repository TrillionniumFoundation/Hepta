from pathlib import Path
import hashlib,json,os,stat,tarfile,gzip,io,base64
R=Path('/workspace/scratch/e26ed3e2edcf/core/v92-recovery-actual-43338002642')
P=R/'small-publication-r2'
F=Path('/tmp/hia-v92-ci-failed-original-parts-r1-20261113-e26e')
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 a=p.lstat();assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  assert ident(a)==ident(os.fstat(fd));out=[]
  while True:
   b=os.read(fd,1<<20)
   if not b:break
   out.append(b)
  raw=b''.join(out);assert ident(a)==ident(os.fstat(fd))==ident(p.lstat()) and len(raw)==a.st_size
 finally:os.close(fd)
 return raw,ident(a)
def save(name,v):
 b=(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
 with (P/name).open('xb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 return pin(b)
old,oldid=read(R/'small-publication/actual-originals.tar.gz')
with tarfile.open(fileobj=io.BytesIO(old),mode='r:gz') as t:
 oldmembers=[{'path':x.name,'bytes':x.size,'sha256':hashlib.sha256(t.extractfile(x).read()).hexdigest()} for x in t]
recon={'schema':'hia.local-archive-authoring-r1-reconciliation.v1','old_partial':{**pin(old),'identity':oldid},'preserved_without_overwrite':True,'observed_members':oldmembers,
 'actual_failure':'AssertionError during before_stat == after_stat in the first archive authoring attempt; only the first five sorted files were added.',
 'diagnosis_limit':'The failed attempt did not retain the two stat objects. A read can change atime, which that tuple equality includes, but the actual unequal field cannot now be proved. No underlying content mutation is inferred.',
 'new_read_predicate':'dev, ino, mode, uid, gid, nlink, size, mtime_ns, ctime_ns checked before/opened/after; atime excluded as access metadata.',
 'product_or_receiver_reexecuted':False,'git_mutation_attempted_for_failed_archive':False}
save('AUTHORING-RECONCILIATION.json',recon)
final=json.loads((R/'small-members/FINAL.json').read_bytes());small=json.loads((R/'small-members/SMALL-READBACK.json').read_bytes())
analysis={'schema':'hia.v92-recovery-43338002642-actual-static-miss.v1','status':'ACTUAL_RECOVERY_HOLD_PRESERVED','recovery_run':43338002642,'job':131599001028,'attempt':1,
 'frozen_A':'89aa086c8e345ecae66cb32a2dd9ff39fe1f35de','frozen_B':'55225e8e954f19e0c6559a6e3d0c29bf16b70ba5',
 'frozen_prefix':'experiments/hia_v92_failed_ci_20261113/multipart-r1/',
 'actual_FINAL':pin((R/'small-members/FINAL.json').read_bytes()),'actual_SMALL_READBACK':pin((R/'small-members/SMALL-READBACK.json').read_bytes()),
 'cause':{'caller':'control/controller.py:755 capture_diagnostics calls relocate_slice(folder/name,destination/name,record)',
  'callee_predicate':"source.name startswith part-; source.suffix .bin; source.parent.name parts; target.name in (slice.bin, unverified-range.bin)",
  'incompatible_actual_inputs':'diagnostics/INDEX.json, DIRECTORY.jsonl, FULL-INVENTORY.jsonl, and 460 selected member-*.bin paths',
  'observed_refusals':463,'selected_diagnostic_files_copied':0},
 'static_review_miss':'The hia_remote_audit author and static review retained all old helper text and checked fixed selection but failed to join the new caller path shape to relocate_slice admissibility. The 74 recorded checks were static only and did not execute this caller/helper combination. Old records remain unmodified.',
 'actual_owned_read':{'closed_echild':True,'worker_rc':0,'owner_seconds':34.293314099,'worker_seconds':34.20256505,'events':4,'timeout':False,'remaining_descendants':[]},
 'limits_unchanged':{'owner_seconds':900,'cleanup_seconds':3,'worker_seconds':720},
 'original_native_failure_diagnosis':'Still UNKNOWN until the original step42 bodies are obtained; the reported missing paths are not a body read.',
 'new_consumer_scope':'New independent read-only operation over three already uploaded immutable official containers, not rerunning this receiver or native CI.',
 'all_three_large_part_GETs_so_far':0,'part_artifacts':[{'ordinal':i,'artifact_id':a,'bytes':s,'sha256':h} for i,a,s,h in [
 (0,13998272481,268838037,'481f17946b97dad14c56ff94cb13ae0033f77d145811dfdd422e5c134fc64e19'),
 (1,13997637506,268838053,'f12a3d4e2c267a23ba487b75abb289c83e06e00dcdb95bb369de8f5442db8c89'),
 (2,13997917943,119894487,'0303930e3e9dae1108d6a656148f1f6eec86a007f2e066469c0f79ba52453d07')]]}
save('ACTUAL-FAILURE-ANALYSIS.json',analysis)
items=[]
for name in ['small-13998357240.original.zip','SMALL-DOWNLOAD-INTENT.json','SMALL-DOWNLOAD-RESULT.json','SMALL-INDEPENDENT-AUDIT.json','SMALL-MEMBERS-MANIFEST.json','audit_small.py']:
 items.append((name,R/name))
for p in sorted((R/'small-members').rglob('*')):
 if p.is_file():items.append((str(p.relative_to(R)),p))
for name in ['FIRST-HEAD-RUNS.raw.json','TERMINAL-RUN.raw.json','TERMINAL-JOBS.raw.json','TERMINAL-ARTIFACTS.raw.json','JOB-131599001028.raw.json','job-131599001028.original.log']:
 items.append(('provider-observation/'+name,F/'actual-observation'/name))
for name in ['AUTHORING-RECONCILIATION.json','ACTUAL-FAILURE-ANALYSIS.json']:
 items.append(('independent/'+name,P/name))
items.append(('authoring-r1/actual-originals.partial.tar.gz',R/'small-publication/actual-originals.tar.gz'))
items.sort();assert len(items)==28 and len({n for n,_ in items})==28
rows=[]
with (P/'actual-originals.tar.gz').open('xb') as outer:
 with gzip.GzipFile(filename='',fileobj=outer,mode='wb',mtime=0,compresslevel=1) as zipped:
  with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT) as archive:
   for name,path in items:
    raw,identity=read(path);row={'member':name,'source':str(path),**pin(raw),'identity':identity};rows.append(row)
    entry=tarfile.TarInfo(name);entry.size=len(raw);entry.mode=0o400;entry.mtime=0;entry.uid=entry.gid=0;archive.addfile(entry,io.BytesIO(raw))
 outer.flush();os.fsync(outer.fileno())
compressed,archive_identity=read(P/'actual-originals.tar.gz')
expected={x['member']:x for x in rows};actual=[]
with tarfile.open(fileobj=io.BytesIO(compressed),mode='r:gz') as archive:
 for member in archive:
  assert member.isfile() and member.name in expected
  raw=archive.extractfile(member).read();row=expected[member.name]
  assert pin(raw)=={k:row[k] for k in pin(raw)}
  path=Path(row['source']);current,current_identity=read(path)
  assert current==raw and current_identity==row['identity'];actual.append(member.name)
assert actual==[x['member'] for x in rows]
save('ARCHIVE-MANIFEST.json',{'schema':'hia.v92-recovery-small-actual-archive.v1','all_body_bytes':sum(x['bytes'] for x in rows),'members':rows,'archive':pin(compressed),'full_archive_members_recovered_and_equal_to_originals':True,'readback_members':len(actual),'original_recovery_status':'HOLD','no_large_part_GETs':True,'private_provider_ref_and_proxy_files_excluded':True})
encoded=base64.b64encode(compressed).decode('ascii');chunks=[]
for i,off in enumerate(range(0,len(encoded),98304)):
 name='archive-%03d.base64'%i;b=encoded[off:off+98304].encode('ascii')+b'\n'
 with (P/name).open('xb') as f:f.write(b)
 chunks.append({'path':name,'base64_offset':off,'encoded_characters':len(b)-1,**pin(b)})
save('ARCHIVE-PARTS.json',{'schema':'hia.byte-preserving-base64-archive-parts.v1','archive':pin(compressed),'encoding':'concatenated ASCII base64, strip exactly one final LF per part','parts':chunks,'whole_decoded_sha256_checked':hashlib.sha256(base64.b64decode(''.join((P/x['path']).read_text().removesuffix('\n') for x in chunks),validate=True)).hexdigest()})
print(json.dumps({'status':'COMPLETE_SMALL_ACTUAL_ARCHIVE_READBACK_PASS_OLD_HOLD_RETAINED','originals':len(rows),'raw_bytes':sum(x['bytes'] for x in rows),'archive':pin(compressed),'base64_parts':len(chunks)}))
