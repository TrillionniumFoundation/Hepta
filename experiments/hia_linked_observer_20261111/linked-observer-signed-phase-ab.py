"""One fresh signed phase: exact original calls, no profiler or cold claim."""
from pathlib import Path
from hashlib import sha256
import json,os,secrets,shutil,sys,tempfile,time

repo=Path(sys.argv[1]).resolve();sys.path.insert(0,str(repo))
out=Path(sys.argv[2]).resolve();out.mkdir(mode=0o700,exist_ok=False)
mode=sys.argv[3];assert mode in ('original-python-linked','hia-linked-observer')
from tools import qualify_hia_selfhost as q
from tools import hia_selfhost_native_observer as flat
from tools import hia_selfhost_linked_observer as linked
from tools import hia_selfhost_signed_cases as signed
from tools.hia_evidence_archive import OWNER,archive_completed_stage

compiler=Path('/workspace/scratch/e26ed3e2edcf/journal-recovered-development-r1/development-compiler.bin')
compiler_sha=sha256(compiler.read_bytes()).hexdigest()
assert compiler_sha=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
feature_paths=['tools/qualify_hia_selfhost.py','tools/hia_selfhost_native_observer.py',
 'tools/hia_selfhost_linked_observer.py','tools/generate_hia_linked_observer.py',
 'tools/hia_linked_observer_bridge.S','examples/hia_bootstrap/linked_observer_policy.hiaasm',
 'examples/hia_bootstrap/linked_observer_packer.hiaasm','tests/test_hia_selfhost_linked_observer.py']
identity=lambda:{p:sha256((repo/p).read_bytes()).hexdigest() for p in feature_paths}
before=q.source_manifest();feature_before=identity()
root=Path(tempfile.mkdtemp(prefix='hia-e26e-linked-signed-'+mode+'-',dir='/tmp'))
helpers=root/'observers';helpers.mkdir(mode=0o700)
started=time.monotonic_ns()
flat_reference=flat.independent_reference();flat_image,flat_receipt=flat.build(helpers,compiler,flat_reference)
flat_build_ns=time.monotonic_ns()-started
linked_image=None;linked_build_ns=0
if mode=='hia-linked-observer':
 started=time.monotonic_ns();linked_reference=linked.independent_reference()
 linked_image,linked_receipt=linked.build(helpers,compiler,linked_reference)
 linked_build_ns=time.monotonic_ns()-started
 (helpers/'independent-reference.json').write_text(json.dumps(linked_reference,sort_keys=True,indent=2)+'\n')
reference_started=time.monotonic_ns();reference=signed.independent_reference();reference_ns=time.monotonic_ns()-reference_started
stage=root/'signed-original';stage.mkdir(mode=0o700);token=secrets.token_hex(32);(stage/OWNER).write_text(token)
q.NATIVE_OBSERVER=flat_image;q.NATIVE_LINKED_OBSERVER=linked_image
checks={};started=time.monotonic_ns()
observations=signed.qualify(stage,(('original',compiler),),checks,reference)
elapsed=time.monotonic_ns()-started
q.NATIVE_OBSERVER=None;q.NATIVE_LINKED_OBSERVER=None
assert len(checks)==326 and all(type(v) is bool and v for v in checks.values())
assert before==q.source_manifest() and feature_before==identity()
receipts=[]
keys=('status','returncode','result_u64','abi_status','core_u32','source_sha256','image_sha256',
 'output_sha256','source_unchanged','output_unchanged','workspace_header','limits',
 'shared_output_observation','forbidden_compiler_modules_loaded')
for path in sorted(stage.glob('*.receipt.json')):
 value=json.loads(path.read_bytes())
 receipts.append({'name':path.name,'status':value['status'],'wall_ns':value['wall_elapsed_ns'],
 'native_ns':value.get('native_elapsed_ns'),'format':value['format'],
 'input_sha256':value['input_sha256'],'artifact_sha256':value['artifact_sha256'],
 'semantic_observation':{k:value[k] for k in keys if k in value}})
assert len(receipts)==458
report={'schema':'hia.linked-observer.development-signed-phase.v1','scope':'DEVELOPMENT ONLY; one full original signed phase; reused historical compiler; no cold/fixed-point claim',
 'base_commit':'4161e8d12d87906fde144f039da07908ad52d98a','compiler_sha256':compiler_sha,
 'source_manifest':before,'feature_source_sha256':feature_before,'source_preserved':True,
 'mode':mode,'wall_elapsed_ns':elapsed,'profiler_enabled':False,
 'fresh_driver_pid':os.getpid(),'python_isolated':bool(sys.flags.isolated),'python_no_site':bool(sys.flags.no_site),
 'flat_observer_build_ns':flat_build_ns,'new_linked_observer_build_and_VM_ns':linked_build_ns,
 'reference_sha256':sha256(json.dumps(reference,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
 'independent_reference_ns':reference_ns,'reference_counts':{k:len(reference[k]) for k in ('cases','refusals','traps')},
 'checks':checks,'observations':observations,'receipts':receipts,'temporary_directory':str(root)}
(out/'signed-native.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
sealed=archive_completed_stage(stage,token);archive=Path(sealed['archive']);saved=out/'signed-native-originals.zip'
with archive.open('rb') as src,saved.open('xb') as dst:
 shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
assert sha256(saved.read_bytes()).hexdigest()==sealed['archive_sha256']
(out/'signed-native-retention.json').write_text(json.dumps(sealed,sort_keys=True,indent=2)+'\n')
# Preserve each freshly produced helper as a separate complete verified stage.
helper_token=secrets.token_hex(32);(helpers/OWNER).write_text(helper_token)
helper_sealed=archive_completed_stage(helpers,helper_token);helper_archive=Path(helper_sealed['archive'])
with helper_archive.open('rb') as src,(out/'observer-build-originals.zip').open('xb') as dst:
 shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())
assert sha256((out/'observer-build-originals.zip').read_bytes()).hexdigest()==helper_sealed['archive_sha256']
(out/'observer-build-retention.json').write_text(json.dumps(helper_sealed,sort_keys=True,indent=2)+'\n')
print(json.dumps({'directory':str(out),'mode':mode,'phase_seconds':elapsed/1e9,
 'new_linked_build_and_VM_seconds':linked_build_ns/1e9,'reference_seconds':reference_ns/1e9,
 'checks':len(checks),'actual_invocations':len(receipts),
 'groups':{f:{'invocations':sum(r['format']==f for r in receipts),
  'wall_ns':sum(r['wall_ns'] for r in receipts if r['format']==f),
  'native_ns_known':sum(r['native_ns'] or 0 for r in receipts if r['format']==f)}
  for f in sorted({r['format'] for r in receipts})},
 'archive_bytes':saved.stat().st_size,'archive_sha256':sealed['archive_sha256']}),flush=True)
