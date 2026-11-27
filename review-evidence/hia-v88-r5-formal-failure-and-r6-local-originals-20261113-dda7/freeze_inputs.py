"""Read-only freeze of the exact completed scopes requested by Root."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,stat,time
ROOT=Path(__file__).resolve().parent
WORK=ROOT.parent
R5=WORK/'v87-source-r5-original';R6=WORK/'v87-union-r6'

def canonical(x):return (json.dumps(x,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
def byte_identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def read_identity(path):
 before=path.lstat()
 if stat.S_ISLNK(before.st_mode):
  data=os.fsencode(os.readlink(path));kind='symlink';row=byte_identity(data)
 elif stat.S_ISREG(before.st_mode):
  kind='file';sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(before.st_size).encode()+b'\0');size=0
  with path.open('rb') as stream:
   while True:
    block=stream.read(1<<20)
    if not block:break
    sha.update(block);git.update(block);size+=len(block)
  row={'bytes':size,'sha256':sha.hexdigest(),'git_blob':git.hexdigest()};assert size==before.st_size,path
 else:raise AssertionError(('unsupported original file type',str(path)))
 after=path.lstat();fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns');assert all(getattr(before,f)==getattr(after,f) for f in fields),path
 row.update({'kind':kind,'mode':format(stat.S_IMODE(before.st_mode),'04o'),'source':str(path),'source_stat':{f:getattr(before,f) for f in fields}})
 return row

def tree_id(rows):
 root={}
 for path,row in rows.items():
  parts=PurePosixPath(path).parts;node=root
  for part in parts[:-1]:node=node.setdefault(part,{})
  assert parts[-1] not in node
  node[parts[-1]]=('120000' if row['kind']=='symlink' else ('100755' if int(row['mode'],8)&0o111 else '100644'),row['git_blob'])
 def walk(node):
  entries=[]
  for name,value in node.items():
   if isinstance(value,dict):mode,sha='40000',walk(value);key=(name+'/').encode()
   else:mode,sha=value;key=name.encode()
   entries.append((key,mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
  raw=b''.join(row for _,row in sorted(entries));return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 return walk(root)

def main():
 started=time.monotonic_ns();nodes={};directories={};groups={};excluded=[]
 def add(path,name,group):
  assert name not in nodes;nodes[name]=read_identity(path);groups.setdefault(group,[]).append(name)
 def folder(path,prefix,group,exclude_git=False):
  assert path.is_dir() and not path.is_symlink(),path
  for current,dirs,files in os.walk(path,followlinks=False):
   current=Path(current);rel=current.relative_to(path)
   if exclude_git and '.git' in dirs:dirs.remove('.git');excluded.append(str(current/'.git'))
   for name in list(dirs):
    p=current/name
    if p.is_symlink():dirs.remove(name);add(p,(PurePosixPath(prefix)/rel/name).as_posix(),group)
   dname=(PurePosixPath(prefix)/rel).as_posix();directories[dname]={'mode':format(stat.S_IMODE(current.lstat().st_mode),'04o')}
   for name in sorted(files):
    if exclude_git and name=='.git':excluded.append(str(current/name));continue
    add(current/name,(PurePosixPath(prefix)/rel/name).as_posix(),group)
 folder(R5/'artifact','r5-formal/artifact','r5_artifact_all_extracted_and_derived')
 folder(R5/'candidate-ci314','r5-formal/candidate-ci314','r5_source3024',True)
 for p in sorted(R5.iterdir()):
  if p.is_file() and p.suffix in ('.py','.json','.log'):add(p,'r5-formal/root/'+p.name,'r5_root_py_json_log')
 folder(R6/'local-generation-r1/evidence','r6-local/local-generation-r1/evidence','r6_generation_evidence')
 folder(R6/'registration-controls-r1/evidence','r6-local/registration-controls-r1/evidence','r6_source140_evidence')
 folder(R6/'local-source-r1','r6-local/local-source-r1','r6_source3024',True)
 for p in sorted(R6.iterdir()):
  if p.is_file() and p.suffix in ('.py','.json','.log'):add(p,'r6-local/root/'+p.name,'r6_root_py_json_log')
 folder(R6/'harness','r6-local/harness','r6_harness',True)
 folder(R6/'published-harness','r6-local/published-harness','r6_published_harness',True)
 add(WORK/'v87-native-development-audit-r2/ROOT-READBACK.json','previous-audit/ROOT-READBACK.json','previous_audit_readback')
 r5readback=json.loads((R5/'artifact/ARTIFACT-FULL-READBACK.json').read_text())
 r5source=json.loads((R5/'artifact/raw/checks/SOURCE-TESTS.json').read_text())
 r6generation=json.loads((R6/'local-generation-r1/evidence/raw/LOCAL-RESULT.json').read_text())
 r6source=json.loads((R6/'registration-controls-r1/evidence/raw/JOINT-SOURCE-TESTS.json').read_text())
 assert len(groups['r5_source3024'])==len(groups['r6_source3024'])==3024
 r5tree=tree_id({k.removeprefix('r5-formal/candidate-ci314/'):nodes[k] for k in groups['r5_source3024']})
 r6tree=tree_id({k.removeprefix('r6-local/local-source-r1/'):nodes[k] for k in groups['r6_source3024']})
 assert r5tree==r5readback['candidate_tree']
 assert r5source['status']=='FAIL' and r5source['tests_run']==1224 and len(r5source['failures'])==10 and not r5source['errors'] and not r5source['skipped']
 assert r5readback['status']=='PASS' and r5readback['source_status']=='FAIL' and r5readback['outer_all_crc'] is True
 assert r6generation['status']=='LOCAL_GENERATION_PASS' and r6generation['generation']['tree']==r6tree
 assert r6source['status']=='PASS' and r6source['tests_run']==140
 outer=read_identity(R5/'artifact.zip');assert outer['bytes']==109945006 and outer['sha256']=='533a25c8f61c3412ef50137fb4be2a8c4ee9ac59c3972acd3c6959a1539e3e4e'
 outer.update({'included_in_new_git_archive':False,'actual_local_full_bytes_sha256_rechecked':True,'prior_root_complete_crc_report':nodes['r5-formal/artifact/ARTIFACT-FULL-READBACK.json'],'prior_root_outer_member_count':r5readback['outer_members'],'not_claimed_reconstructible_from_members':True,'original_actions_metadata':nodes['r5-formal/root/ARTIFACTS.json']})
 summary={'r5_formal':{'status':'SOURCE_FAIL','runtime':'CPython 3.14.4','run':43415454682,'job':131852076482,'harness_commit':'29b1145e37db05d5efa62d75c4d1dd5916f1f8b4','tests_run':1224,'failures':10,'errors':0,'skipped':0,'evidence_integrity_status':'PASS','source_tree':r5tree,'source_files':3024,'outer_original_zip':outer},'r6_local':{'status':'LOCAL_GENERATION_AND_TARGETED_SOURCE_PASS','runtime':'CPython 3.12.14','generation':r6generation['generation'],'syntax':r6generation['syntax'],'targeted_source_methods':140,'source_tree':r6tree,'source_files':3024,'formal_run_43422327653_result_not_included':True},'no_new_product_or_test_execution':True,'no_source_or_product_or_audit_ref_changes':True,'whole_native':False}
 plan={'schema':'hepta.completed-original-scopes-custody.v1','created_utc_ns':time.time_ns(),'logical_files':nodes,'directories':directories,'logical_count':len(nodes),'logical_bytes':sum(x['bytes'] for x in nodes.values()),'groups':{g:{'count':len(paths),'bytes':sum(nodes[p]['bytes'] for p in paths),'paths':paths} for g,paths in groups.items()},'excluded_git':excluded,'intentional_exclusions':['R5 artifact.zip exact original byte container (identity and prior full CRC retained; original local/Actions kept)','Root independently owned old R5 local 5397-member / 81-wrapper scope','formal R6 future/in-progress output','R6 input-blobs/ and source/ not requested; complete final local-source-r1 and all harness source packets included'],'scope_summary':summary,'fixed_inputs_only':True,'self_contained_logical_originals':True,'historical_execution_environment_requires_original_Git_dependencies':True,'elapsed_ns':time.monotonic_ns()-started}
 (ROOT/'INPUTS-FROZEN.json').write_bytes(canonical(plan));(ROOT/'SCOPE-SUMMARY.json').write_bytes(canonical(summary));(ROOT/'OUTER-ZIP-RETENTION.json').write_bytes(canonical(outer))
 print(json.dumps({'logical_count':plan['logical_count'],'logical_bytes':plan['logical_bytes'],'directories':len(directories),'groups':{g:{'count':row['count'],'bytes':row['bytes']} for g,row in plan['groups'].items()},'r5_tree':r5tree,'r6_tree':r6tree,'elapsed_ns':plan['elapsed_ns']},sort_keys=True))
if __name__=='__main__':main()
