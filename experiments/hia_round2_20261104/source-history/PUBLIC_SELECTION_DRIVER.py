"""Select the small public source-history handoff; copy no395MB object pack."""
from pathlib import Path
import base64,hashlib,json,os,subprocess,time
B=Path('/data/hepta-hia-round2-20261104/evidence')
LOCAL=B/'source-portable-r2/public'
OUT=B/'source-history-public-compact-r3'
PUB=OUT/'public'
H='5ee6d8fec0e5c72d87a36dbed60789de211abf1b'
T='d47a711461dc66d4606bdc9659203889e205d6c7'
F2='f2b76f5741c83822be2e12cf5a50b50a8d27b96a'
def req(v,m):
 if not v:raise ValueError(m)
def save(p,j):
 b=(json.dumps(j,indent=2,sort_keys=True,ensure_ascii=True)+'\n').encode();p.open('xb').write(b)
 return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def copy(p,q):
 b=p.read_bytes();q.parent.mkdir(parents=True,exist_ok=True);q.open('xb').write(b)
 req(q.read_bytes()==b,'copy mismatch')
 return {'path':q.relative_to(PUB).as_posix(),'original_path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
start=time.monotonic_ns();OUT.mkdir();PUB.mkdir();records=[]
local=json.loads((LOCAL/'PACKAGE_RESULT.json').read_bytes())
req(local['passed'] is True and local['restore']['passed'] is True,'local restore did not pass')
req(local['source']=={'commit':H,'tree':T} and local['source_unchanged'] is True,'local source differs')
for p in sorted(LOCAL.rglob('*')):
 if not p.is_file():continue
 rel=p.relative_to(LOCAL).as_posix()
 if rel.startswith('objects.pack.part-') or rel in ('README.md','PACKAGING_DRIVER.py'):continue
 rename={'MANIFEST.json':'LOCAL_PORTABLE_MANIFEST.json','PACKAGE_RESULT.json':'LOCAL_PORTABLE_PACKAGE_RESULT.json','RESTORE.py':'LOCAL_PORTABLE_RESTORE.py','LAUNCH_PLAN.json':'LOCAL_PORTABLE_LAUNCH_PLAN.json'}
 records.append(copy(p,PUB/rename.get(rel,rel)))
records.append(copy(LOCAL/'PACKAGING_DRIVER.py',PUB/'LOCAL_PORTABLE_PACKAGING_DRIVER.py'))
records.append(copy(B/'source-portable-r2/EXPORT_RESULT.json',PUB/'LOCAL_EXPORT_RESULT.json'))
env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')};env.update(GIT_NO_LAZY_FETCH='1',GIT_NO_REPLACE_OBJECTS='1',GIT_OPTIONAL_LOCKS='0')
repo=Path('/data/hepta-hia-round2-20261104/work-integration')
raw=subprocess.check_output(['git','cat-file','commit',H],cwd=repo,env=env,timeout=20)
req(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==H,'raw original commit differs')
(PUB/'ORIGINAL_COMMIT.raw').open('xb').write(raw)
records.append({'path':'ORIGINAL_COMMIT.raw','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_commit':H})
records.append(copy(B/'final-source-history/commands/006-original-tree.stdout',PUB/'ORIGINAL_TREE_RECORDS.z'))
records.append(copy(Path(__file__),PUB/'PUBLIC_SELECTION_DRIVER.py'))
bundle=json.loads((PUB/'INCREMENTAL_BUNDLE.json').read_bytes());whole=hashlib.sha256();size=0
for p in bundle['parts']:
 b=(PUB/p['name']).read_bytes();req(len(b)==p['bytes'] and hashlib.sha256(b).hexdigest()==p['sha256'],'bundle part differs');whole.update(b);size+=len(b)
req(size==3634207 and whole.hexdigest()==bundle['bundle']['sha256']=='0e0b8628a22f23836b2ba0002e475cec83a6e1b53b088896d8e3fd1ff2ca6367','incremental bundle differs')
manifest={'schema':'hepta.hia.public-original-source-handoff.v1','source':{'commit':H,'tree':T},'public_same_tree_projection':'3102c2bb6cd819c27aef36cc927c23b39b279204','public_repository':'https://github.com/TrillionniumFoundation/Hepta','public_prefix':'experiments/hia_round2_20261104/source-history/','original_bundle':bundle,'public_bundle_requires_external_base_object_closure':True,'required_base_commit':F2,'public_package_is_self_contained_full_history':False,'complete_public_ancestry_acquisition_succeeded':False,'network_retry_count':0,'local_offline_restore_passed':True,'local_objects':8361,'local_visible_commits':53,'restored_tracked_paths':8946,'actual_shallow_boundary':'931c96fcc7fb698226b809862c233a345dcca4ec','locally_retained_not_uploaded_object_pack':{'path':str(B/'source-portable-r2/objects.pack'),'bytes':local['pack']['bytes'],'sha256':local['pack']['sha256'],'parts':len(local['pack']['parts']),'reason':'Avoid duplicating395MB of Git objects already represented in the published same-tree source. The raw pack and its fully verified fresh independent store remain on the operator host; this public handoff preserves original incremental history, exact identities and restoration evidence.'},'files':records,'scope':'Publication selection only. No compiler, model, native benchmark, proof, Git fetch or requalification. Original900s public fetch failure remains a failure; local real-shallow restore is a separate delivery result.'}
save(PUB/'PUBLIC_MANIFEST.json',manifest)
readme='''# Original measured source: public handoff

The measured original commit is `5ee6d8fec0e5c72d87a36dbed60789de211abf1b`, with complete tree `d47a711461dc66d4606bdc9659203889e205d6c7`. Public commit `3102c2bb6cd819c27aef36cc927c23b39b279204` contains the same complete source tree. It is an App publication projection; it must not be substituted for the original measured commit identity.

This small package publishes the original3,634,207-byte incremental Git bundle in five ordered parts, raw original commit bytes, full8946-path tree/blob inventory, exact actual shallow boundary, all failed-fetch control/log receipts, and the complete result of a separate successful offline restoration. It does **not** publish the395,845,206-byte duplicate object pack or claim to contain complete public history. `LOCAL_PORTABLE_MANIFEST.json` records the omitted pack and its504 parts; those part files are deliberately absent from this public package. `LOCAL_PORTABLE_RESTORE.py` is the actual procedure used on the operator host, and requires that separately retained local full pack to run.

## Reconstruct the original commit with the public prerequisite

Use a repository already containing the full public prerequisite object closure at `f2b76f5741c83822be2e12cf5a50b50a8d27b96a`. Rejoin `original-source.bundle.part-*` in lexical order and verify SHA256 `0e0b8628a22f23836b2ba0002e475cec83a6e1b53b088896d8e3fd1ff2ca6367`. Then run `git bundle verify` and fetch the bundle's `HEAD` into a new branch. Verify the restored original commit and tree above. The bundle is incremental and does not supply the prerequisite closure by itself. The old command receipts include the exact successful bundle header/list-heads checks.

Our attempt to obtain that complete public base over the network reached its original900-second delivery timeout. The failure remains recorded; it was not retried or relabeled. To verify source availability without another network attempt, we independently packed the8361 objects already present locally, including53 visible commits, restored them in an empty bare repository, ran strict fsck and checked every one of the8946 source paths. That local offline restore passed while explicitly retaining the original shallow boundary `931c96fcc7fb698226b809862c233a345dcca4ec`. The original shallow file repeats the same boundary twice; the restore deduplicated only that same boundary. No missing ancestry was invented.

The original full desktop shared-proof qualifier still failed its600-second outer budget. Neither the source restoration nor later proof replay reverses that failure. This package is delivery evidence; it executes no experiment and grants no production authority. Private NDU sources, toolchains, external Cargo dependencies and model weights are outside this source handoff.
'''
(PUB/'README.md').open('x').write(readme)
status=subprocess.check_output(['git','status','--porcelain=v1','--untracked-files=all'],cwd=repo,env=env,timeout=20)
req(status==b'' and subprocess.check_output(['git','rev-parse','HEAD','HEAD^{tree}'],cwd=repo,env=env,timeout=20).decode().splitlines()==[H,T],'source changed')
result=save(PUB/'PUBLIC_SELECTION_RESULT.json',{'passed':True,'source_unchanged':True,'original_bundle_verified':True,'published_raw_pack':False,'publication_scope_only':True,'no_experiment_rerun':True,'wall_ns':time.monotonic_ns()-start})
transport=OUT/'base64-export';transport.mkdir();rows=[]
for p in sorted(PUB.rglob('*')):
 if not p.is_file():continue
 b=p.read_bytes();folder=transport/f'{len(rows):04d}';folder.mkdir();parts=[]
 for n,i in enumerate(range(0,len(b),48000)):
  q=folder/f'{n:05d}.base64';q.open('xb').write(base64.b64encode(b[i:i+48000]));parts.append(str(q))
 rows.append({'path':p.relative_to(PUB).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'mode':'100644','transport_parts':parts})
idx=save(transport/'INDEX.json',{'files':rows,'count':len(rows),'bytes':sum(r['bytes'] for r in rows),'public_root':str(PUB),'chunk_decoded_bytes':48000})
outer=save(OUT/'STAGING_RESULT.json',{'selection_result':result,'transport':idx,'wall_ns':time.monotonic_ns()-start,'scope':'Small publication-selection copying/hash/base64 staging only; no new compression, full-tree hash scan, compiler, native, model, proof or network operation.'})
print(json.dumps({'result':outer,'transport':idx,'files':len(rows),'bytes':sum(r['bytes'] for r in rows)},sort_keys=True))
