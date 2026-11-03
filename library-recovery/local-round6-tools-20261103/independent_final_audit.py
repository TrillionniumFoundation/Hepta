#!/usr/bin/env python3
"""Independent read-only recovery-package audit; executes no packaged/project code."""
from pathlib import Path,PurePosixPath
import ast,collections,datetime,hashlib,io,json,lzma,os,re,stat,subprocess,tarfile,zipfile
W=Path('/workspace/scratch/bf7d454bbc83');R=W/'round6-recovery';B=W/'round6-recovered-ci-publication';PREFIX='evidence/hia_round6_ci_recovered_20261029';P=B/PREFIX
H='9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b';T='debee7040ed2ffac2cbaf953c28c1e2ca3fc8407';EXPECTED='784db49f1dcf3cb59344049b3bd4a15cfd612aa5';SUBTREE='6b43d90a6852a0c5b2c2d9e48e45238dde179e39';AH='33b1639a6a23f0086d187e9b72f7fdd913e163eab91164df090a631bd3092967'
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):assert stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink();return p.read_bytes()
def load(p):return json.loads(read(p))
def binding(p):b=read(p);return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def safe(n):
 p=PurePosixPath(n);assert n and n==p.as_posix() and not p.is_absolute() and '..' not in p.parts and '\\' not in n and ':' not in n and not any(ord(c)<32 for c in n);return p
selb=read(B/'INPUT_SELECTION.json');assert sha(selb)=='7284f3e1028342e1d483ad55380a5375e88d20987d9b1213c00932dfa6a5c0cb';sel=json.loads(selb)
assert sel['source_commit']==H and sel['source_tree']==T and sel['old_complete_package_restored'] is False and sel['private_original_verified_zip_included'] is False
expected={};component_records=[]
for comp in sel['components']:
 c=comp['component'];mp=R/c/comp['manifest'];mb=read(mp);assert len(mb)==comp['manifest_bytes'] and sha(mb)==comp['manifest_sha256'];m=json.loads(mb)
 rows={}
 for row in m['files']:
  name=row['archive_relative'] if c=='metadata' else row['path'];safe(name);assert name not in rows;rows[name]=row
 extras=[comp['manifest']]+(['PUBLIC_FREEZE.json'] if c=='host' else [])
 for name in extras:
  assert name not in rows;b=read(R/c/name);rows[name]={'bytes':len(b),'sha256':sha(b)}
 assert len(rows)==comp['selected_file_count'] and sum(v['bytes'] for v in rows.values())==comp['selected_bytes']
 for name,row in rows.items():expected[c+'/'+name]={'bytes':row['bytes'],'sha256':row['sha256']}
 component_records.append({'component':c,'manifest':binding(mp),'files':len(rows),'bytes':comp['selected_bytes']})
assert len(expected)==257 and sum(v['bytes'] for v in expected.values())==101508375
selected={v['archive_relative']:v for v in sel['files']};assert set(selected)==set(expected) and len(sel['files'])==257
signed=[]
for name,row in selected.items():
 safe(name);c=row['component'];rel=row['component_relative'];assert name==c+'/'+rel and c in ('host','metadata','integrated','verified')
 p=R/c/rel;assert p.resolve().is_relative_to((R/c).resolve());data=read(p);assert len(data)==row['bytes']==expected[name]['bytes'] and sha(data)==row['sha256']==expected[name]['sha256']
 assert not {'private-transfer','private-quarantine','private-artifacts','retrieval-attempts'}.intersection(PurePosixPath(name).parts)
 if not name.endswith('.zip'):
  data.decode('utf-8');assert b'\0' not in data
  if re.search(rb'[?&](?:sig|token|signature|X-Amz-Signature|X-Goog-Signature)=[A-Za-z0-9%_+/-]{8,}',data,re.I):signed.append(name)
assert not signed
host=load(R/'host/PUBLIC_FILE_MANIFEST.json');hostzip={'host/artifacts/'+str(i)+'/original.zip' for i in host['public_original_zip_ids']};zipnames={n for n in expected if n.endswith('.zip')};assert zipnames==hostzip|{'integrated/artifact-12898192961.zip'} and len(zipnames)==16
vm=load(R/'verified/PUBLIC_RECOVERY_MANIFEST.json');original_verified=[v for v in vm['files'] if v['kind']=='original_ci_zip_member'];assert len(original_verified)==122 and sum(v['bytes'] for v in original_verified)==6420254
assert not any(n.startswith('verified/') and n.endswith('.zip') for n in expected)
public_selection=load(P/'RECOVERY-SELECTION.json');assert public_selection=={**sel,'input_selection_sha256':sha(selb),'old_complete_package_restored':False}
a=load(P/'ARCHIVE.json');ib=read(P/'RAW-INDEX.json');index=json.loads(ib);assert len(ib)==a['index']['bytes'] and sha(ib)==a['index']['sha256']
assert a['source_commit']==index['source_commit']==H and a['source_tree']==index['source_tree']==T and a['old_397_file_package_restored'] is False and a['newly_assembled_recovery'] is True
assert a['private_original_verified_zip_included'] is False and index['private_original_verified_zip_included'] is False and index['original_file_bytes_modified'] is False
ir={v['path']:v for v in index['files']};assert len(ir)==len(index['files'])==257 and set(ir)==set(expected)
for n,row in ir.items():assert row['bytes']==expected[n]['bytes'] and row['sha256']==expected[n]['sha256'] and row['mode']==0o644
assert a['file_count']==index['file_count']==257 and a['uncompressed_file_bytes']==index['bytes']==101508375
parts=[]
for i,row in enumerate(a['parts'],1):
 assert row['path']==f'parts/raw-evidence.tar.xz.part{i:03d}';data=read(P/row['path']);assert len(data)==row['bytes']<=6291456 and sha(data)==row['sha256'];parts.append(data)
joined=b''.join(parts);assert len(parts)==11 and len(joined)==a['bytes']==65305268 and sha(joined)==a['sha256']==AH
seen=set();total=0
with lzma.LZMAFile(io.BytesIO(joined),'rb') as dec:
 with tarfile.open(fileobj=dec,mode='r|') as tar:
  for info in tar:
   name=info.name;safe(name);assert name in ir and name not in seen and info.isfile() and not info.islnk() and not info.issym() and not info.linkname
   assert info.mode==0o644 and info.uid==info.gid==info.mtime==0 and info.uname==info.gname=='' and info.size==ir[name]['bytes']
   h=hashlib.sha256();size=0
   with tar.extractfile(info) as f:
    while chunk:=f.read(1024*1024):h.update(chunk);size+=len(chunk)
   assert size==ir[name]['bytes'] and h.hexdigest()==ir[name]['sha256'];seen.add(name);total+=size
 tail=dec.read();assert not tail or set(tail)=={0}
assert seen==set(ir) and total==101508375
# Cross-check every nested-member index. HostZIPs were freshly CRC/hash-audited;
# independently read the integrated original ZIP's46members here.
assert len(index['zip_expansions'])==16 and {v['archive'] for v in index['zip_expansions']}==zipnames
members=0;expanded_bytes=0
for ex in index['zip_expansions']:
 n=ex['archive'];rows=ex['members'];assert len(rows)==ex['member_count'] and len({v['path'] for v in rows})==len(rows)
 if n.startswith('host/'):
  artifact_id=PurePosixPath(n).parts[2];rr=load(R/'host/artifacts'/artifact_id/'PUBLIC_MEMBER_REVIEW.json');other={v['path']:v for v in rr['members']};assert rr['public_archive_eligible'] is True
 else:
  assert sha(read(R/n))=='098599b4febdaf01511ec4faff0f791b48d3e6a913c68ec6f0d1554f026caec1';other={}
  with zipfile.ZipFile(R/n) as z:
   for info in z.infolist():
    safe(info.filename);assert not info.is_dir() and stat.S_IFMT(info.external_attr>>16)==stat.S_IFREG and not info.flag_bits&1
    data=z.read(info);data.decode('utf-8');assert b'\0' not in data;other[info.filename]={'bytes':len(data),'sha256':sha(data),'mode':info.external_attr>>16}
 assert set(other)=={v['path'] for v in rows}
 for row in rows:
  safe(row['path']);orig=other[row['path']];assert row['bytes']==orig['bytes'] and row['sha256']==orig['sha256'] and row['mode']==(orig['mode']&0o777)
 assert ex['bytes']==sum(v['bytes'] for v in rows);members+=len(rows);expanded_bytes+=ex['bytes']
assert members==5087 and expanded_bytes==377158633
# Official fresh source/terminal snapshot, without re-executing any CI check.
obs=R/'metadata/observations/20261029T145802929Z';runs=load(obs/'runs.json')['workflow_runs'];jobs=[]
for p in obs.glob('*-jobs.json'):jobs+=load(p)['jobs']
assert len(runs)==6 and len(jobs)==len({v['id'] for v in jobs})==18
assert all(v['head_sha']==H and v['status']=='completed' and v['conclusion']=='success' for v in runs+jobs) and all(v['run_attempt']==1 for v in runs)
# Verify the reader algorithm identity by reversing exactly the two declared edits.
rb=read(P/'RESTORE.py');text=rb.decode();original=text.replace('Verify/restore newly assembled round-six recovered CI observations.','Verify/restore recovered CI observations.').replace('hepta.hia-round6-ci-recovered.restore-verification.v1','hepta.hia-round5-recovered.restore-verification.v1').encode()
assert sha(original)=='523c432662c68556316c7d866e72b46a75ffc7a6b019d1d9b948e85daf8a59e4' and len(original)==8000
prov=load(P/'READER-PROVENANCE.json');assert prov['new_reader_sha256']==sha(rb)=='1b8e2a6d03afa1937ffb9344a018679edc5b767e8f417af1bf104efb41391410' and prov['original_sha256']==sha(original) and prov['verification_and_restoration_logic_changed'] is False
verifyb=read(P/'VERIFY_ONLY.json');verify=json.loads(verifyb);assembly=load(P/'ASSEMBLY-VERIFICATION.json')
assert verify['all_passed'] is True and verify['source_commit']==H and verify['archive_sha256']==AH and verify['parts']==11 and verify['raw_files']==257 and verify['raw_file_bytes']==101508375 and verify['ci_expanded_files']==verify['ci_expanded_bytes']==0 and verify['output'] is None and verify['project_code_executed'] is False
assert assembly['returncode']==0 and assembly['stdout_sha256']==sha(verifyb) and assembly['stderr_bytes']==0 and assembly['source_before']==assembly['source_after']==index['source_snapshot'] and assembly['source_unchanged'] is True
assert assembly['source_before']['head']==H and assembly['source_before']['tree']==T and assembly['source_before']['status']=='' and assembly['archive_sha256']==AH and assembly['selection_sha256']==sha(selb)
assert read(B/'VERIFY_ONLY.stdout.log')==verifyb and read(B/'VERIFY_ONLY.stderr.log')==b'' and read(P/'.gitattributes')==b'* -text\n'
# Review final21-public-file identities and compute the complete Git tree anew.
freezeb=read(B/'PACKAGE-FREEZE.json');planb=read(B/'UPLOAD-PLAN.json');tsb=read(B/'TREE-SHAS.json')
assert sha(freezeb)=='c38f99209862c7ec3b5b30c5cedee8f22a0507d47333e8601885b8019f206bc8' and sha(planb)=='207594bf51374ee337f886ca8aac845bac668f423dbbe261ac9260176616497d' and sha(tsb)=='e353097c5e1a60e2531d66dfe7169c5623f46098238372540dc7300984a0b7ef'
freeze=json.loads(freezeb);plan=json.loads(planb);ts=json.loads(tsb)
assert plan['base_commit']==plan['sole_parent']==H and plan['commit_parents']==[H] and plan['base_tree']==freeze['source_tree']==T and plan['prefix']==freeze['prefix']==PREFIX
assert plan['git_objects_or_refs_written'] is False and plan['remote_operations_performed'] is False and freeze['further_public_file_mutation_allowed'] is False
assert len(plan['blobs'])==len(freeze['files'])==plan['blob_count']==freeze['public_file_count']==21
fixed={v['path']:v for v in freeze['files']};assert len(fixed)==21 and set(fixed)=={v['path'] for v in plan['blobs']}
actual={p.relative_to(P).as_posix() for p in P.rglob('*') if p.is_file()};assert actual=={v['relative'] for v in plan['blobs']}
def git(kind,data):return hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()
env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'};repo=W/'hepta-round6-integration'
source_raw=subprocess.check_output(['git','--no-replace-objects','ls-tree','-r','-z','--full-tree',H],cwd=repo,env=env)
assert sha(source_raw)==freeze['source_ls_tree_sha256']==assembly['source_before']['tracked_tree_sha256']
source={}
for row in source_raw.split(b'\0'):
 if not row:continue
 meta,n=row.split(b'\t',1);mode,kind,oid=meta.decode().split();assert kind=='blob';source[n.decode()]=(mode,oid)
assert len(source)==6410 and not any(n==PREFIX or n.startswith(PREFIX+'/') for n in source)
merged=dict(source);public_bytes=0
for row in plan['blobs']:
 n=row['path'];rel=row['relative'];safe(rel);assert n==PREFIX+'/'+rel and row['local_path']==str(P/rel) and row['mode']=='100644' and row['type']=='blob'
 assert {k:v for k,v in row.items() if k!='encoding'}==fixed[n]
 data=read(P/rel);assert len(data)==row['bytes'] and sha(data)==row['sha256'] and git('blob',data)==row['git_blob_sha1'];public_bytes+=len(data)
 assert row['encoding']==('base64' if rel.startswith('parts/') else 'utf-8');merged[n]=('100644',row['git_blob_sha1'])
assert public_bytes==freeze['public_bytes']==66646636

def trees(entries):
 root={};objects={}
 for path,v in entries.items():
  cursor=root;parts=path.split('/')
  for part in parts[:-1]:cursor=cursor.setdefault(part,{})
  assert parts[-1] not in cursor;cursor[parts[-1]]=v
 def encode(node,path):
  records=[];api=[]
  for name,v in node.items():
   isdir=isinstance(v,dict);mode,oid=('40000',encode(v,path+name+'/')) if isdir else v
   records.append(((name+('/' if isdir else '')).encode(),mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)))
   api.append({'path':name,'mode':'040000' if isdir else mode,'sha':oid,'type':'tree' if isdir else 'blob'})
  data=b''.join(v for _,v in sorted(records));oid=git('tree',data);objects[path.rstrip('/')]=(oid,len(data),{v['path']:v for v in api});return oid
 return encode(root,''),objects
base,oldobjs=trees(source);new,objs=trees(merged);assert base==T and new==EXPECTED==plan['expected_root_tree_sha1']==freeze['new_expected_root_tree_sha1']==ts['new_root_tree'] and objs[PREFIX][0]==SUBTREE
assert {k:v for k,v in merged.items() if not k.startswith(PREFIX+'/')}==source and len(merged)==6431==plan['final_file_paths']
assert len(plan['trees_bottom_up'])==plan['tree_count']==len(ts['trees'])==4
for req,summary in zip(plan['trees_bottom_up'],ts['trees']):
 path=req['path'];oid,length,full=objs[path]
 assert req['expected_tree_sha1']==summary['expected_tree_sha1']==oid and req['serialized_tree_bytes']==length and req['base_tree_sha1']==summary['base_tree_sha1']
 if req['base_tree_sha1'] is not None:assert oldobjs[path][0]==req['base_tree_sha1']
 entries={v['path']:v for v in req['entries']};assert len(entries)==len(req['entries']) and all(set(v)=={'path','mode','sha','type'} for v in req['entries']) and entries==full
summary=load(P/'PACKAGE-SUMMARY.json');assert summary['source_commit']==H and summary['source_tree']==T and summary['raw_file_count']==257 and summary['raw_file_bytes']==101508375 and summary['archive_sha256']==AH
assert summary['all_six_research_goals_closed'] is False and summary['old_unpublished_397_file_package_restored'] is False and summary['new_project_tests_or_ci_reruns']==0
assert summary['integrated']['python_unique_methods']==3898 and summary['integrated']['rust_tests']==84 and summary['integrated']['cargo_result_sections']==16 and summary['integrated']['canonical_selectors']==146 and summary['integrated']['gates_passed']==8
readme=read(P/'README.md').decode();assert '16 Cargo result sections' in readme and '397-file' in readme and 'has not been restored' in readme and '257' in readme and AH in readme
report={'schema':'hepta.round6.recovered-package-independent-review.v1','reviewed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reviewer':'migration_guard_integration','status':'no_concrete_publication_blocker','activity':{'project_tests_or_compilers_run':False,'archived_programs_or_RESTORE_executed_by_reviewer':False,'GitHub_writes':False,'source_or_frozen_package_mutation':False,'method':'Read-only byte/hash checks, complete XZ/tar stream traversal, nested member index comparison, actual46-member integratedZIP reads, official API terminal comparison, two-edit reader reverse-hash and independent pureGit tree encoding.'},'source_commit':H,'source_tree':T,'input_selection':binding(B/'INPUT_SELECTION.json'),'components':component_records,'raw_files':257,'raw_bytes':101508375,'all_raw_selection_bytes_sizes_paths_and_component_manifest_membership_checked':True,'all_16_original_ZIP_bytes_official_digest_bound':True,'private_original_verified_ZIP_included':False,'verified_original_public_members':122,'verified_original_public_bytes':6420254,'signed_transfer_query_patterns_detected':signed,'archive':{'metadata':binding(P/'ARCHIVE.json'),'index':binding(P/'RAW-INDEX.json'),'bytes':len(joined),'sha256':sha(joined),'parts':11,'all_part_hashes_and_whole_XZ_checksum_checked':True,'all257TAR_payloads_and_regular_modes_matched':True,'ZIPs':16,'indexed_ZIP_members':5087,'indexed_ZIP_member_bytes':377158633},'fresh_CI_observation':{'directory':str(obs),'workflows':6,'jobs':18,'exact_source_all_terminal_success':True,'run_attempt':1,'not_a_new_CI_execution':True},'reader':{'retained':binding(P/'RESTORE.py'),'provenance':binding(P/'READER-PROVENANCE.json'),'reverse_only_description_and_output_schema_matches_original523c_sha256':True,'producer_actual_verify_receipt':binding(P/'VERIFY_ONLY.json'),'producer_assembly_record':binding(P/'ASSEMBLY-VERIFICATION.json'),'producer_exit':0,'producer_stderr_bytes':0,'reviewer_did_not_execute_reader':True},'publication':{'freeze':binding(B/'PACKAGE-FREEZE.json'),'plan':binding(B/'UPLOAD-PLAN.json'),'tree_identities':binding(B/'TREE-SHAS.json'),'public_files':21,'public_bytes':public_bytes,'sole_parent':H,'new_prefix':PREFIX,'expected_root_tree_independently_computed':new,'expected_prefix_tree_independently_computed':objs[PREFIX][0],'expected_parts_tree_independently_computed':objs[PREFIX+'/parts'][0],'unchanged_original_paths_modes_Git_blob_ids':6410,'all21_blob_size_SHA256_Git_SHA1_modes_encodings_match':True,'all_four_bottom_up_requests_checked_against_complete_trees':True,'full_path21_SHA_only_create_tree_equivalent':True,'remote_publication_not_performed_by_reviewer':True},'readme':binding(P/'README.md'),'scope_notes':['This is a NEW257-file recovery, with new metadata/review timestamps. The former unpublished397-file package and its65,891,552-byte/396fd5... archive are not claimed restored or published.','15host/six ZIPs were newly downloaded by this reviewer and completely CRC/SHA/path/type/budget checked. The integrated originalZIP was recovered by root and independently read here.','The verified privateZIP remains outside the selection; only122original report members and explicitly labelled new/official metadata are included.','The source-bound original CI denominators3898Python/84Rust/146canonical/777verified/351six/host repetitions remain separate and are not added.16Cargo result sections mean15Running sections plus one emptyDoc-tests section.','Native/foreign-library safety remains scoped; negative NDU and runtime economic findings remain negative. This review grants no whole-language safety or global-optimality claim.','Two preliminary inspection snippets assumed an older plan files key; the final audit explicitly checks the recovered-plan blobs/trees schema. No source/package or original report bytes were changed.'],'blockers':[]}
out=B/'INDEPENDENT-FINAL-REVIEW.json';out.write_bytes((json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode());print(json.dumps({'review':binding(out),'root':new,'subtree':objs[PREFIX][0],'files':21,'bytes':public_bytes,'status':report['status']},sort_keys=True))
