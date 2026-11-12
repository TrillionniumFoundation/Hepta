"""Canonical Git tree plan: overlay verified blobs, preserve every prior path."""
from pathlib import Path,PurePosixPath
import hashlib,json,sys
B=Path(__file__).resolve().parent
base=json.loads((B/'base-tree56.json').read_bytes());assert not base['truncated'] and base['sha']=='32336492843e1dd8e321f9fc7a1239a0aa6d01af'
payload=json.loads((B/'publication-payload.json').read_bytes());rows=payload['rows']
def build(files):
 dirs={'':{}}
 for path,row in files.items():
  p=PurePosixPath(path);assert not p.is_absolute() and '..' not in p.parts and '.' not in p.parts
  parent=str(p.parent);parent='' if parent=='.' else parent
  dirs.setdefault(parent,{})[p.name]={'path':p.name,'mode':row['mode'],'type':row.get('type','blob'),'sha':row['sha']}
  q=parent
  while q:
   pp=str(PurePosixPath(q).parent);pp='' if pp=='.' else pp;dirs.setdefault(pp,{});dirs.setdefault(q,{});q=pp
 result={}
 for path in sorted(dirs,key=lambda p:(p.count('/')+1 if p else 0,p),reverse=True):
  entries=list(dirs[path].values());entries.sort(key=lambda e:(e['path']+('/' if e['type']=='tree' else '')).encode())
  body=b''.join((('40000' if r['type']=='tree' else r['mode'])+' '+r['path']).encode()+b'\0'+bytes.fromhex(r['sha']) for r in entries)
  sha=hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).hexdigest();result[path]={'path':path,'sha':sha,'tree_elements':entries}
  if path:
   p=PurePosixPath(path);parent=str(p.parent);parent='' if parent=='.' else parent;dirs[parent][p.name]={'path':p.name,'mode':'040000','type':'tree','sha':sha}
 return result
oldfiles={r['path']:{**r} for r in base['tree'] if r['type']!='tree'};assert len(oldfiles)==9230
old=build(oldfiles);oldpins={r['path']:r['sha'] for r in base['tree'] if r['type']=='tree'};oldpins['']=base['sha'];assert set(old)==set(oldpins)
for p,r in old.items():assert r['sha']==oldpins[p],p
files={p:dict(r) for p,r in oldfiles.items()};seen=set();added=changed=0
for r in rows:
 assert r['path'] not in seen;seen.add(r['path']);assert r['mode'] in ('100644','100755','120000') and len(r['gitsha'])==40 and r['bytes']>=0
 p=r['path'];target={'path':p,'mode':r['mode'],'type':'blob','sha':r['gitsha'],'size':r['bytes']}
 if p not in files:added+=1
 elif any(files[p][k]!=target[k] for k in ('sha','mode','type','size')):changed+=1
 files[p]=target
assert set(oldfiles)<=set(files);new=build(files)
plan=[r for r in new.values() if r['sha']!=oldpins.get(r['path'])];plan.sort(key=lambda r:(r['path'].count('/')+1 if r['path'] else 0,r['path']),reverse=True)
expected=[{k:r[k] for k in ('path','mode','type','sha','size') if k in r} for r in files.values()]+[{'path':p,'mode':'040000','type':'tree','sha':r['sha']} for p,r in new.items() if p]
expected.sort(key=lambda r:r['path']);report={'schema':'hia-root-canonical-no-delete-tree-publication-plan-r1','parent_commit':'d438a5bf52d2ecddf53850e7f2f0fd0a433d2676','base_tree':base['sha'],'base_files':len(oldfiles),'base_trees_including_root':len(old),'all_base_canonical_trees_verified':True,'payload_rows':len(rows),'payload_bytes':sum(r['bytes'] for r in rows),'new_files':added,'changed_files':changed,'deleted_files':0,'new_tree':new['']['sha'],'result_files':len(files),'result_entries':len(expected),'changed_directories':len(plan),'plan':plan,'expected_recursive_entries':expected}
(B/'publication-tree-plan.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('plan','expected_recursive_entries')},sort_keys=True))
