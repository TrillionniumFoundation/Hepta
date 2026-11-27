from pathlib import Path
import json,hashlib
P=Path('/workspace/scratch/dda74a4fae35/v82-service-artifacts-development-r4/ci-r1/terminal-custody-r1')
saved=json.loads((P/'PARTIAL-INDEX-RECOVERY.json').read_bytes())
parts=saved['partial49']['verified_parts']+[json.loads((P/('part-'+str(i)+'.readback.json')).read_bytes()) for i in range(49,58)]
pos=0
for i,row in enumerate(parts):
 assert row['index']==i and row['offset']==pos
 assert row['full_readback_equal'] is True and row['raw_source_slice_equal'] is True
 row['filename']='part-'+str(i).zfill(3)+'.base64'
 pos+=row['raw_bytes']
assert pos==51618568 and len(parts)==58
receipt=json.loads((P/'RECEIPT.json').read_bytes())
manifest=json.loads((P/'MANIFEST.json').read_bytes())
h=hashlib.sha256()
with (P/'COMPLETE-TERMINAL.tar.xz').open('rb') as f:
 while block:=f.read(1<<20):h.update(block)
assert h.hexdigest()==receipt['archive']['sha256']=='50f2c7b20a68b5e93bce6512479fe34cd2afa09eed690b2a2c53e47324eb8536'
index={
 'schema':'hia.lossless-archive.complete-readback-index.v1','complete':True,
 'repository':'TrillionniumFoundation/Hepta',
 'archive':{'bytes':51618568,'sha256':h.hexdigest(),'computed_git_blob':receipt['archive']['git_blob'],'delivery':'ordered independently base64 encoded Git UTF-8 blobs; no standalone binary Git blob claimed'},
 'manifest':{'bytes':receipt['manifest']['bytes'],'sha256':receipt['manifest']['sha256'],'git_blob':'793e272faff007ccd0fd5c5042f4243a10d22278'},
 'local_archive':'/workspace/scratch/dda74a4fae35/v82-service-artifacts-development-r4/ci-r1/terminal-custody-r1/COMPLETE-TERMINAL.tar.xz',
 'part_raw_bytes':900000,'parts':parts,
 'verification':{'all_58_created_and_full_read_back':True,'exact_ordered_source_slices_equal':True,'continuous_raw_coverage_bytes':pos,
  'original_archive_full_tar_xz_roundtrip':receipt,
  'second_large_binary_materialization_from_git_not_performed':True,
  'recovery_helper':'a23c87c55f25d7076157dd1a391a63f9f55c8c7b',
  'recovery_helper_scope':'authored, AST parsed; original archive roundtrip and exact Git-part readbacks verified independently'},
 'original_raw_custody':manifest['complete_original_binary_members'],
 'other_whole_outer_zips':manifest['other_whole_outer_zips'],
 'preserved_transport_observations':{
  'initial_part0_unequal_readback':saved['partial9']['first_readback_failure'],
  'same_blob_second_readback':saved['partial9']['first_readback_later_match'],
  'initial_first_readback_body_not_retained':True,
  'v8_old_keys_unavailable_after_all_58_acks':'restored first49 from verified immutable partial index b773dd014346a8d5f5f91694510d87e272df8290; last9 exact original Git refs fully fetched again and matched original archive slices',
  'package_script_missing_content_validation_rejection':saved['package_script_failed_tool'],
  'local_recovery_helper_extra_lf':json.loads((P/'RECOVERY-COPY-RECONCILIATION.json').read_bytes())
 },
 'small_objects':json.loads((P/'SMALL-OBJECT-READBACKS.json').read_bytes()),
 'scope':manifest['scope']
}
raw=(json.dumps(index,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode()
(P/'INDEX.json').write_bytes(raw)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'parts':len(parts),'coverage':pos}))

