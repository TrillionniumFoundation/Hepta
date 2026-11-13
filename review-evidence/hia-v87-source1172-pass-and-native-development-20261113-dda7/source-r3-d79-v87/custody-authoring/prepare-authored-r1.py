from pathlib import Path
import base64,hashlib,json,shutil,zlib,datetime
OUT=Path(__file__).resolve().parent
SRC=Path('/workspace/scratch/dda74a4fae35/recovered-v85')
DATA=OUT/'files';DATA.mkdir(exist_ok=True)
def identity(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=True,indent=2,sort_keys=True)+'\n')
def copy(rel,target):
 p=DATA/target;p.parent.mkdir(parents=True,exist_ok=True);b=(SRC/rel).read_bytes();p.write_bytes(b);return identity(b)
copy('source-r3-artifact/ARTIFACT-FULL-READBACK.json','ARTIFACT-FULL-READBACK.json')
copy('source-r3-artifact/TREE-DELTA.json','TREE-DELTA.json')
copy('source-r3-artifact/CANDIDATE-LEAVES.json','CANDIDATE-LEAVES.json')
copy('verify_source_r3.py','verify_source_r3.py')
copy('source-r3-diagnostics/FULL-JOB.log','FULL-JOB.log')
copy('source-r3-artifact/raw/RESULT.json','original/RESULT.json')
copy('source-r3-artifact/raw/checks/SOURCE-TESTS.json','original/SOURCE-TESTS.json')
copy('source-r3-artifact/raw/checks/SOURCE-TESTS.events.jsonl','original/SOURCE-TESTS.events.jsonl')
for n in ('COMMIT-READBACK.json','REF-READBACK.json','TREE-VERIFIED.json','PUBLISHED.json'):
 copy('source-r3-diagnostics/published-candidate/'+n,'published-candidate/'+n)
manifest_path=SRC/'source-r3-diagnostics/EVIDENCE-MANIFEST.json';mb=manifest_path.read_bytes();m=json.loads(mb)
assert identity(mb)['git_blob']=='97e52715891c1c498fd765cf009abb3247277d0a'
assert len(m['chunks'])==75
pos=0
for i,c in enumerate(m['chunks']):
 assert c['index']==i and c['offset']==pos and c['full_readback_equal'] is True
 assert c['bytes']>0 and len(c['blob'])==40 and len(c['sha256'])==64
 pos+=c['bytes']
assert pos==m['bytes']==38854610
s=json.loads((DATA/'original/SOURCE-TESTS.json').read_text());r=json.loads((DATA/'original/RESULT.json').read_text())
ids=s['ordered_ids'];assert len(ids)==len(set(ids))==s['expected']==s['tests_run']==1172
assert ids==s['actual_started_ids']==s['actual_stopped_ids'] and s['status']=='PASS' and s['complete'] is True
for n in ['duplicate_ids','errors','expected_failures','failures','missing_a733_ids','missing_frozen_a733_ids','missing_frozen_main_ids','missing_main_ids','skipped','unexpected_successes']:assert s[n]==[],n
assert all(v==[] for v in s['loader_errors'].values())
events=[json.loads(t) for t in (DATA/'original/SOURCE-TESTS.events.jsonl').read_text().splitlines()]
assert events==[{'event':event,'id':name} for name in ids for event in ('start','stop')]
assert len(s['frozen_original_main_ids'])==530 and len(s['frozen_original_a733_projected_ids'])==973
assert all(x in ids for x in s['frozen_original_main_ids']) and all(x in ids for x in s['frozen_original_a733_projected_ids'])
assert r['status']=='SOURCE_PASS' and r['source_tests']==s and r['generation']['generator_count']==109 and r['generation']['real_generation_passes']==2
assert r['syntax']=={'checked':1441,'failures':0} and r['whole_native'] is False and r['cold_qualifications']==0
leaves=json.loads((DATA/'CANDIDATE-LEAVES.json').read_text());root={}
for f in leaves:
 assert f['type']=='blob' and f['mode'] in ('100644','100755','120000')
 node=root;parts=f['path'].split('/')
 for p in parts[:-1]:node=node.setdefault(p,{})
 assert parts[-1] not in node;node[parts[-1]]=f

def tree(node):
 entries=[]
 for name,x in node.items():
  if 'sha' in x and 'mode' in x:mode=x['mode'];sha=x['sha'];key=name.encode()
  else:mode='40000';sha=tree(x);key=(name+'/').encode()
  entries.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
 data=b''.join(value for key,value in sorted(entries))
 return hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
assert len(leaves)==2989 and tree(root)=='279c5459c9cc7746d5e347d90285eebfe21986d2'
commit=json.loads(json.loads((DATA/'published-candidate/COMMIT-READBACK.json').read_text())['structuredContent']['content'])
ref=json.loads(json.loads((DATA/'published-candidate/REF-READBACK.json').read_text())['structuredContent']['content'])
assert commit['sha']=='d79eb096ddcce6c317b2c316a4773ce76a37bab9' and commit['tree']['sha']==tree(root)
parents=[p['sha'] for p in commit['parents']];assert parents==['f33d8da316de8fdf27b504371f1a5310997ff548','a733926a2786a3d4a37304bd2d18ebb2eac57ac9']
assert ref['object']['sha']==commit['sha'] and ref['ref']=='refs/heads/codex/hia-combined-native-v86-d79eb09-20261113-dda7'
# Preserve the connector payloads verbatim inside a compact text capsule.
# The initial wrapper's tool label was copied incorrectly for four responses;
# record both that label and its corrected value, leaving response untouched.
correct={'D79-COMMIT':'github_fetch_commit','SOURCE-R3-JOBS':'github_fetch_workflow_run_jobs','SOURCE-R3-ARTIFACTS':'github_fetch_workflow_run_artifacts','D79-NORMAL-CORE-JOBS':'github_fetch_workflow_run_jobs','D79-BRANCH':'github_search_branches'}
snaps={}
for p in sorted((OUT/'remote').glob('*.json')):
 original=p.read_bytes();x=json.loads(original)
 snaps[p.name]={'original_wrapper_identity':identity(original),'original_wrapper_text':original.decode(),'actual_tool':correct[x['label']],'wrapper_tool_label_error':x['tool'].rsplit('__',1)[-1]!=correct[x['label']]}
raw=json.dumps({'schema':'hepta.source-r3-publication.connector-snapshots.v1','snapshots':snaps},ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()
packed=zlib.compress(raw,6);capsule={'schema':'hia.zlib-source-capsule.v1','encoding':'zlib+base64','raw_bytes':len(raw),'raw_sha256':hashlib.sha256(raw).hexdigest(),'payload':base64.b64encode(packed).decode()}
write(DATA/'CONNECTOR-SNAPSHOTS.zlib.json',capsule)
assert zlib.decompress(base64.b64decode(capsule['payload']))==raw
normal=json.loads((OUT/'remote/D79-NORMAL-CORE-JOBS.json').read_text())
job_summary=[{'id':j['id'],'name':j['name'],'status':j['status'],'conclusion':j['conclusion'],'active_steps':[v['name'] for v in j['steps'] if v['status']=='in_progress']} for j in normal['response']['structuredContent']['jobs']]
readback=json.loads((DATA/'ARTIFACT-FULL-READBACK.json').read_text())
report={'schema':'hepta.source-r3-published-candidate-custody.v1','status':'VERIFIED_SOURCE_PASS_AND_EXACT_PUBLICATION','scope':'READ_ONLY_EVIDENCE_AND_IMMUTABLE_BLOB_CUSTODY','prepared_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'run':43396616508,'job':131788970461,'harness':'68a30237e870d41d2403f9dc3857bcf3e80b376a','source':{'python':r['python'],'status':r['status'],'selectors':len(s['selectors']),'declared_loaded_started_stopped_run':len(ids),'events':len(events),'anomalies':0,'original_main_ids':530,'original_a733_ids':973,'wall_seconds':s['wall_seconds'],'generators':109,'passes':2,'syntax_files':1441,'canonical_physical_migrations':55,'source_files':len(leaves),'independently_recomputed_tree':tree(root)},'publication':{'commit':commit['sha'],'parents':parents,'branch':ref['ref'],'tree':commit['tree']['sha'],'root_original_commit_ref_readbacks_retained':True,'agent_independent_commit_fetch_retained':True,'leaf_list_independently_rehashed':True,'no_new_product_mutation_in_this_task':True},'archive':{'manifest':identity(mb),'chunks':m['chunks'],'bytes':m['bytes'],'sha256':m['sha256'],'original_members':len(m['members']),'original_full_readback_report':identity((DATA/'ARTIFACT-FULL-READBACK.json').read_bytes()),'raw_chunks_reused_by_git_sha_without_reupload_or_recompression':True,'this_agent_did_not_repeat_full_archive_crc':True,'previous_root_complete_byte_mode_crc_validation_retained':True},'outer_zip':{'artifact_id':14025125596,'bytes':readback['zip_bytes'],'sha256':readback['zip_sha256'],'whole_zip_container_git_persistence_claimed':False,'all_logical_evidence_captured_in_75_chunks':True},'normal_core_snapshot':{'run':43402528459,'captured_at':normal['captured_at'],'jobs':job_summary,'terminal_qualification_claimed':False},'limitations':{'native_qualification':False,'matching_cold_qualification':False,'whole_native':False,'legacy_host_tree_deleted':False,'default_ref_changed':False,'original_prepublication_reports_not_rewritten':True,'mutable_ci_snapshot_not_a_final_result':True}}
write(DATA/'REPORT.json',report)
files=[{'path':str(p.relative_to(DATA)),**identity(p.read_bytes())} for p in sorted(DATA.rglob('*')) if p.is_file()]
write(OUT/'UPLOAD-PLAN.json',{'schema':'hepta.source-r3-custody.upload-plan.v1','files':files,'existing_manifest':identity(mb),'existing_chunks':m['chunks']})
print(json.dumps({'status':'PASS','files':len(files),'text_bytes':sum(x['bytes'] for x in files),'source_methods':len(ids),'selectors':len(s['selectors']),'tree':tree(root),'jobs':job_summary,'snapshots_capsule':identity((DATA/'CONNECTOR-SNAPSHOTS.zlib.json').read_bytes())},indent=2))
