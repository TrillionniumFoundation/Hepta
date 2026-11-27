from pathlib import Path
import base64, hashlib, json, zlib
ROOT=Path(__file__).resolve().parent
PARENT=ROOT.parent
def identity(b):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(name,obj):
 b=(json.dumps(obj,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
 with (ROOT/name).open('xb') as f:f.write(b)
 return identity(b)
def main():
 transport=json.loads((ROOT/'TRANSPORT.json').read_bytes())
 restoration=json.loads((ROOT/'git-readback-restore-r1/REPORT.json').read_bytes())
 assert restoration['status']=='ALL_GIT_GET_LOGICAL_ORIGINALS_RESTORED'
 receipts=[]
 for row in transport['chunks']:
  r=json.loads((ROOT/'GIT-CUSTODY'/(row['file']+'.receipt.json')).read_bytes())
  assert r['full_get_verified'] is True and r['git_blob']==row['git_blob']
  receipts.append(r)
 assert len(receipts)==56
 members={}
 for p in sorted((ROOT/'GIT-CUSTODY').rglob('*.json')):
  if 'readback' in p.relative_to(ROOT/'GIT-CUSTODY').parts:continue
  b=p.read_bytes();members[p.relative_to(ROOT).as_posix()]={**identity(b),'text':b.decode()}
 raw=(json.dumps({'schema':'hepta.custody.exact-utf8-transfer-records.v1','members':members},sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
 wrapper={'schema':'hepta.custody.zlib-base64-utf8.v1','decoded':identity(raw),'members':len(members),'payload':base64.b64encode(zlib.compress(raw,9)).decode()}
 transfer_meta=write('TRANSFER-RECEIPTS.zlib.json',wrapper)
 assert zlib.decompress(base64.b64decode(wrapper['payload'],validate=True))==raw
 index={
  'schema':'hepta.hia.process-cold-complete-custody.v1',
  'status':'COMPLETE_GIT_GET_AND_ACTUAL_RESTORE',
  'logical_members':1339,'logical_bytes':101776815,'unique_cas_objects':853,'tar_members':854,
  'raw_chunk_count':56,'all_wrappers_post_ack_full_get':True,
  'archive':transport['archive'],'raw_archive_binary_git_upload_claim':False,
  'full_restore':restoration,'transfer_records':{'file':'TRANSFER-RECEIPTS.zlib.json',**transfer_meta,'members':len(members)},
  'source_tree':'3a1c42c02bee93486b1cb440b2f44a8b32dccf65',
  'fixed_unchanged_source_baseline':{'tree':'d91c9154cbed9cc1473aad4e152049dc21c6ab9d','files':3064,'embedded_in_this_archive':False},
  'source_packet':'49341a9888619f8d7bca0f585d230b2eb0491f2d',
  'registration_spec':'088bdbe10f9afd6ed0d7f32078a388deb904e54f',
  'results':[
   {'scope':'first_source_revision','actual_methods':87,'status':'PASS','runtime':'CPython 3.12','current_cold':False},
   {'scope':'first_actual_portable_revision','actual_methods':1,'status':'PASS','runtime':'CPython 3.12','current_cold':False},
   {'scope':'successor_source_revision','actual_methods':17,'status':'PASS','runtime':'CPython 3.12','current_cold':False},
   {'scope':'successor_portable_readback','status':'READBACK_PASS','new_product_commands':0,'not_a_portable_reexecution':True}],
  'matching_current_source_cold_positive':'NOT_EXECUTED','actual_314_native':'NOT_EXECUTED','whole_native':False,
  'historical_original_process_development_raw_recipe':'a66c166016fb9a7012bd45d257080c92ec9f5f27',
  'publication_anomalies':[
   {'scope':'source-publication','kind':'preflight_GET_RemoteProtocolError','recovery':'actual fixed GET 404 then one POST ACK/full GET; raw response retained in logical originals'},
   {'scope':'raw-batch-scheduler','kind':'local verification process yielded after one second; original scheduler incorrectly required immediate exit','recovery':'resumed exact session69091 terminal0; chunks48/49 already ACK/fullGET; no extra POST; preserved original error and recovery terminal; R2 waits yielded session'}],
  'audit_ref_mutation':False
 }
 write('INDEX.json',index)
 files=['MANIFEST.json','LOCAL-READBACK.json','TRANSPORT.json','PUBLICATION-HASH-UTILITY.js','PUBLICATION-HELPER.js','restore.py',
        'PUBLICATION-HELPER-R2.js','PUBLICATION-TWO-CHUNK-SCHEDULER.js','PUBLICATION-TWO-CHUNK-SCHEDULER-R2.js',
        'run_git_readback_restore.py','finalize_process_custody.py','TRANSFER-RECEIPTS.zlib.json','INDEX.json','README.md',
        'git-readback-restore-r1/REQUEST.json','git-readback-restore-r1/stdout','git-readback-restore-r1/stderr','git-readback-restore-r1/REPORT.json']
 publish=[{'file':f,**identity((ROOT/f).read_bytes())} for f in files]
 write('FINAL-PUBLISH-LIST.json',publish)
 print(json.dumps({'logical':1339,'chunks':len(receipts),'transfer_records':len(members),'final_metadata':len(publish),'complete_restore':True}))
if __name__=='__main__':main()
