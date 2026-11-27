from pathlib import Path,PurePosixPath
import hashlib,io,json,stat,tarfile
root=Path('/workspace/scratch/dda74a4fae35');out=root/'v74-root-evidence-r1';out.mkdir(mode=0o700)
selected={}
def add(path,name):
 p=Path(path);assert p.is_file() and not p.is_symlink();assert name not in selected;selected[name]=p
for name in ['v74-harness-local-r1/LOCAL-MATERIALIZATION-AST.json','recovered-originals/ac3-component-recovery.json','recovered-originals/source-admission-r1-r3-member-recovery.json','v74-local-development-generation-r1.py']:
 add(root/name,'root-development/'+name)
for folder in ['v74-local-development-generation-r1','v74-stream-publication-development-r1','v74-stream-missing-helper-development-r2']:
 for p in sorted((root/folder).rglob('*')):
  if p.is_file():add(p,'root-development/'+str(p.relative_to(root)))
for rev in ['v74-core-receipt-fixture-r2','v74-core-receipt-fixture-r3']:
 base=root/rev
 for p in sorted((base/'evidence').rglob('*')):
  if p.is_file():add(p,'root-development/'+str(p.relative_to(root)))
 for name in ['preservation.json','original-test_hia_standalone_builder_source_binding.py','source/tests/test_hia_standalone_builder_source_binding.py']:
  p=base/name
  if p.is_file():add(p,'root-development/'+str(p.relative_to(root)))
for name in ['hia-cold.json','hia-cold.cold/qualification.json','hia-cold.cold/qualification.evidence/B3.image.bin','hia-cold.cold/qualification.evidence/B3.receipt.json']:
 add(root/'recovered-originals/ac3-raw'/name,'original-ac3/'+name)
base=root/'recovered-originals/v74-source-harness-43149993963'
for name in ['RECOVERY.json','hia-source-v74-driver.stdout','hia-source-v74-driver.stderr','hia-source-v74-evidence/EVIDENCE-ZIP-RECEIPT.json']:
 add(base/name,'original-source-run-43149993963/'+name)
member_root=base/'hia-source-v74-evidence/original-members'
for p in sorted(member_root.rglob('*')):
 if p.is_file():add(p,'original-source-run-43149993963/members/'+str(p.relative_to(member_root)))
rows={}
for name,p in selected.items():
 b=p.read_bytes();rows[name]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode)}
manifest={'schema':'hepta.hia.root-execution-evidence.v74','members':rows,'member_count':len(rows),'original_failed_source_run_status':'FAIL','local_first_stream_panel_status':'FAIL_MISSING_ORIGINAL_TEST_HELPER','local_single_missing_helper_retry_status':'PASS','local_first_receipt_fixture_revision_status':'FAIL_ZERO_ARGUMENT_STUB','local_corrected_receipt_fixture_module_status':'PASS_14','original_source_run_all_482_member_bytes_preserved':True,'original_source_run_compressed_ZIP_bytes_included':False,'original_source_run_artifact_id':13914411644,'original_source_run_artifact_sha256':'6272768fadfadf753cfbf4b0f5a46b6109068ce8bbcaaf137bd4bdd81d8d6a75','current_source_cold_qualified':False,'whole_native_delivery_qualified':False,'historical_unknown_job_replayed':False}
manifest_raw=(json.dumps(manifest,indent=2)+'\n').encode();(out/'MANIFEST.json').write_bytes(manifest_raw)
archive=out/'v74-root-execution-originals.tar.xz'
with tarfile.open(archive,'w:xz',preset=6) as tar:
 for name,p in sorted(selected.items()):
  raw=p.read_bytes();e=rows[name];assert len(raw)==e['bytes'] and hashlib.sha256(raw).hexdigest()==e['sha256']
  info=tarfile.TarInfo(name);info.size=len(raw);info.mode=e['mode'];info.mtime=0;tar.addfile(info,io.BytesIO(raw))
 info=tarfile.TarInfo('MANIFEST.json');info.size=len(manifest_raw);info.mode=0o644;info.mtime=0;tar.addfile(info,io.BytesIO(manifest_raw))
with tarfile.open(archive,'r:xz') as tar:
 members=tar.getmembers();assert len(members)==len(rows)+1 and len({m.name for m in members})==len(members)
 for m in members:
  raw=tar.extractfile(m).read()
  if m.name=='MANIFEST.json':assert raw==manifest_raw
  else:
   e=rows[m.name];assert len(raw)==e['bytes'] and hashlib.sha256(raw).hexdigest()==e['sha256'] and m.mode==e['mode']
b=archive.read_bytes();receipt={'schema':'hepta.hia.root-execution-evidence-archive.v74','archive_path':str(archive),'archive_bytes':len(b),'archive_sha256':hashlib.sha256(b).hexdigest(),'member_count':len(rows)+1,'all_member_bytes_hashes_modes_reread':True,'uncompressed_member_bytes':sum(x['bytes'] for x in rows.values())+len(manifest_raw),'manifest_sha256':hashlib.sha256(manifest_raw).hexdigest(),'all_original_failed_outcomes_retained':True,'current_source_cold_qualified':False,'whole_native_delivery_qualified':False}
(out/'ARCHIVE.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))