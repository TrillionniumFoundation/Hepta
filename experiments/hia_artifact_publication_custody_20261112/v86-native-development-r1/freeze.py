"""Create the reviewable v86 request. This script executes no HIA or test body."""
import ast
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import sys

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
CONTROL = ROOT / 'control'
PAIR = Path('/tmp/hia-publication-compiler-pair-v85-r1')
OUTPUT = Path('/tmp/hia-sha-v86-development-actual-r1')

def pin(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    assert Path(path).read_bytes() == raw
    return {'path': str(path), **pin(path)}

material = json.loads((CONTROL / 'SOURCE.json').read_bytes())
assert material['commit'] == '83106d7bc1a96e2b899261e78c85a652b1fd71eb'
assert material['tree'] == '731173a4da0440f781f55e19a71ebd5cd1eff20b'
assert material['canonical_leaves'] == 4051 and material['physical_files'] == 1813
pins = {row['path']: {k: row[k] for k in ('bytes','sha256','mode','git_blob_sha1')} for row in material['files']}
actual = sorted(p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*') if p.is_file())
assert actual == sorted(pins)
for name, expected in pins.items():
    path = SOURCE / name; raw = path.read_bytes()
    assert not path.is_symlink() and pin(path) == {k: expected[k] for k in ('bytes','sha256')}
    assert stat.S_IMODE(path.stat().st_mode) == int(expected['mode'][-3:], 8)
    assert sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['git_blob_sha1']
support = json.loads((SOURCE/'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes())
declared = support['source_identity']['files']
assert len(declared) == 815 and all(pins[name]['sha256'] == digest for name, digest in declared.items())

original = {}; mapping = {}; method_pins = {}; fixture_pins = {}
for module, cls, key, development, count in [
    ('test_hia_sha256_native', 'Sha256HiaNativeTests', 'one_shot', 'DevelopmentOneShotCases', 7),
    ('test_hia_sha256_stream_native', 'Sha256StreamNativeTests', 'stream', 'DevelopmentStreamCases', 5),
]:
    path = SOURCE/'tests'/(module+'.py'); text = path.read_text()
    value = next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name==cls)
    methods = sorted((n for n in value.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')), key=lambda n:n.name)
    assert len(methods)==count
    ids = []
    for node in methods:
        name='tests.'+module+'.'+cls+'.'+node.name
        ids.append(name); mapping['__main__.sha_phase.<locals>.'+development+'.'+node.name]=name
        raw=ast.get_source_segment(text,node).encode()
        method_pins[name]={'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
    original[key]=ids
    for node in value.body:
        if isinstance(node,ast.FunctionDef) and node.name in ('setUpClass','tearDownClass'):
            raw=ast.get_source_segment(text,node).encode()
            fixture_pins['tests.'+module+'.'+cls+'.'+node.name]={
                'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'executed':False}

quota='test_quota_is_original_64MiB_and_never_applied_to_generic_publisher'
for module, cls, names in [
    ('test_hia_agent_artifact_store_native','AgentArtifactStoreKernelTests',[quota,'run_store','setUp']),
    ('test_hia_artifact_publication_native','ArtifactPublicationKernelTests',['run_app','setUp']),
]:
    text=(SOURCE/'tests'/(module+'.py')).read_text()
    value=next(n for n in ast.parse(text).body if isinstance(n,ast.ClassDef) and n.name==cls)
    for name in names:
        node=next(n for n in value.body if isinstance(n,ast.FunctionDef) and n.name==name)
        raw=ast.get_source_segment(text,node).encode()
        method_pins['tests.'+module+'.'+cls+'.'+name]={'bytes':len(raw),'sha256':sha256(raw).hexdigest()}

magic_text=(SOURCE/'tools/generate_hia_artifact_publication.py').read_text()
magic_node=next(n for n in ast.parse(magic_text).body if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name) and t.id=='MAGIC' for t in n.targets))
assert ast.get_source_segment(magic_text,magic_node)=="MAGIC=int.from_bytes(b'HIAPUB01','little')"

inputs = {}
for key, path in {
    'compiler': PAIR/'worker/v82/B3.image.bin',
    'policy_image':PAIR/'worker/v82/artifact_publication_policy.image.bin',
    'packer_image':PAIR/'worker/v82/artifact_publication_packer.image.bin',
    'policy_source':PAIR/'worker/v82/artifact_publication_policy.input.bin',
    'packer_source':PAIR/'worker/v82/artifact_publication_packer.input.bin',
    'prior_pair_final':PAIR/'FINAL.json',
    'prior_pair_owner':PAIR/'owner.json',
    'prior_pair_owner_request':PAIR/'owner.json.request.json',
    'prior_pair_worker':PAIR/'worker/REPORT.json',
    'prior_pair_v82':PAIR/'worker/v82/RESULT.json',
}.items():
    assert path.is_file() and not path.is_symlink() and path.stat().st_nlink==1
    inputs[key]={'path':str(path),**pin(path)}
assert inputs['compiler']['bytes']==670467
assert inputs['compiler']['sha256']=='9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892'
for key in ('policy','packer'):
    expected=pins['examples/hia_bootstrap/artifact_publication_'+key+'.hiaasm']
    assert {k:inputs[key+'_source'][k] for k in ('bytes','sha256')}=={k:expected[k] for k in ('bytes','sha256')}
config={
    'schema':'hepta.hia.v86-native-development-config.v1',
    'candidate':{'commit':material['commit'],'tree':material['tree'],'canonical_leaves':4051,
                 'profile':support['profile'],'source_scope':material['scope'],
                 'physical_files':1813,'physical_bytes':material['bytes'],'declared_source_files':815},
    'source_path':str(SOURCE),'output_path':str(OUTPUT),'source_pins':pins,
    'controls':{name:pin(CONTROL/name) for name in ('common.py','controller.py','worker.py','SOURCE.json')},
    'python':{'executable':sys.executable,'resolved_executable':str(Path(sys.executable).resolve()),
              'version':sys.version,'binary':pin(Path(sys.executable).resolve()),
              'platform':platform.platform()},
    'inputs':inputs,'environment_PATH':os.environ['PATH'],
    'publication_magic':int.from_bytes(b'HIAPUB01','little'),
    'sha_original_ids':original,'development_method_map':mapping,
    'original_method_body_pins':method_pins,'original_nonexecuted_fixtures':fixture_pins,
    'publication_method_ids':[
        '__main__.publication_phase.<locals>.DevelopmentQuotaCase.'+quota,
        '__main__.publication_phase.<locals>.DevelopmentGenericCase.test_generic_publish_accepts_same_first_overquota_payload'],
    'limits':{'phase_seconds':180,'cleanup_seconds':3,'compile_wall_seconds':20,
              'compile_CPU_seconds':10,'compile_capacity':1<<20,'store_call_seconds':60,'generic_call_seconds':30},
    'reuse_provenance':{'kind':'EXISTING_COMPILER_AND_TWO_PREVIOUSLY_COMPILED_UNCHANGED_SOURCE_IMAGES',
        'actual_pair_evidence_commit':'2f76bf1ba7827734bd469d062cd0802a4e001f31',
        'actual_pair_evidence_prefix':'experiments/hia_artifact_publication_custody_20261112/v85-r1/compiler-pair-result-r1/',
        'fresh_cold':False,'original_CI_deleted_application_recovered':False},
    'scope':{'native_class_count':0,'original_method_bodies':12,'development_subclasses':2,
        'original_fresh_native_setUpClass':False,'original_VM_setUpClass_precheck':False,
        'original_quota_method_bodies':1,'new_generic_publish_measurements':1,'runtime_calls':5,
        'new_compiles':2,'new_native_pack_calls':1,'original_39_suite':False,
        'original_publication_step_had_overall_180_owner':False,
        'new_independent_phase_owners':2,'fresh_cold':False,'standard_CI':False},
}
config_pin=write(CONTROL/'CONFIG.json',config)
command=[sys.executable,'-I','-B',str(CONTROL/'controller.py'),'--config',str(CONTROL/'CONFIG.json'),
         '--config-sha256',config_pin['sha256'],'--source',str(SOURCE),'--output',str(OUTPUT)]
record={'schema':'hepta.hia.v86-native-development-preexec.v1','status':'FROZEN_UNEXECUTED_REQUIRES_ROOT_REVIEW',
        'command':command,'cwd':str(SOURCE),'config':config_pin,'controls':config['controls'],
        'candidate':config['candidate'],'python':config['python'],'sealed_external_inputs':inputs,
        'limits':config['limits'],'scope':config['scope'],
        'two_new_180_plus_3_owners_not_one_original_publication_limit':True,
        'expected_minimum_retained_runtime_bytes_approx':400<<20,
        'original_failure_remains':'v82 publication accepted store-put exceeded its unchanged 60-second call bound.',
        'original_pair_result':'Four earlier compiled policy/packer/stream/app outputs were byte-identical across the two existing B3 compilers.',
        'causal_or_flaky_conclusion':False,'retry_after_unknown_execution':False,
        'new_CI_or_ref_trigger':False,'fresh_or_standard_qualification_claim':False}
write(CONTROL/'PREEXEC.json',record)
print(json.dumps({'config':config_pin,'preexec':pin(CONTROL/'PREEXEC.json'),'source_files':len(pins),
                  'original_sha_methods':len(mapping),'product_executed':False}))
