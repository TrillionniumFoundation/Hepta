"""Source-only r2/r3 inverse identity and immutable gate checks."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import json
import sys
import yaml

root=Path(__file__).resolve().parent
old=root.parent/'native116-metadata-r2'
def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
            'git_blob_sha1':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
a=yaml.load((old/'workflow-template.yml.txt').read_text(),Loader=yaml.BaseLoader)
b=yaml.load((root/'workflow-template.yml.txt').read_text(),Loader=yaml.BaseLoader)
oldp=json.loads((old/'policy.json').read_text());p=json.loads((root/'policy.json').read_text())
oldsteps=a['jobs']['native_development']['steps'];steps=b['jobs']['native_development']['steps']
assert len(oldsteps)==len(steps)==12
for before,after in zip(oldsteps,steps):
    for field in ('name','timeout-minutes','if','uses'):
        assert before.get(field)==after.get(field),field
for field in ('timeout-minutes','permissions','runs-on'):
    assert a['jobs']['native_development'][field]==b['jobs']['native_development'][field]
assert a['permissions']==b['permissions']
assert p['candidate']==oldp['candidate']
assert (root/'expected-tests.json').read_bytes()==(old/'expected-tests.json').read_bytes()
ids=[i for group in p['test_groups'].values() for i in group['ids']]
assert len(ids)==len(set(ids))==116
assert [group['count'] for group in p['test_groups'].values()]==[15,51,50]
assert len(p['unit_names'])==39
syntax=[]
for name,expected in p['controls'].items():
    raw=(root/name).read_bytes();ast.parse(raw.decode());compile(raw,name,'exec')
    assert pin(raw)==expected,name
    syntax.append(name)
assert sha256((root/'policy.json').read_bytes()).hexdigest() in (root/'workflow-template.yml.txt').read_text()
inverse=(root/'workflow-template.yml.txt').read_text()
for before,after in [('native-development-r3','native-development-r2'),('run-r3-20261112-e26e','run-r2-20261112-e26e'),('runtime-metadata-r3-','runtime-metadata-r2-'),('native development r3','native development r2'),(sha256((root/'policy.json').read_bytes()).hexdigest(),sha256((old/'policy.json').read_bytes()).hexdigest())]:
    inverse=inverse.replace(before,after)
assert inverse==(old/'workflow-template.yml.txt').read_text()
assert p['phase_controller_seconds']==180 and p['cleanup_seconds']==3
assert p['compile_child_wall_seconds']==20 and p['compile_child_CPU_seconds']==10
assert p['original_compile_capacity_bytes']==1048576 and p['guardian_request_capacity_bytes']==262144
assert p['runtime_metadata_provisioning']['report_raw_bound_per_stage']==131072
assert p['runtime_metadata_provisioning']['stdout_bound_per_stage']==196608
report={'schema':'hia.core-emitter-native-r3-source-controls.v1','status':'PASS',
        'scope':'Local Python3.12 syntax/YAML/inverse byte and source identity checks; no Actions, compiler, native, or product execution.',
        'runtime':sys.version,'sources':{name:pin((root/name).read_bytes()) for name in syntax},
        'declared_yaml_steps':12,'whole_workflow_inverse_identity_and_policy_projection_byte_equal':True,
        'same_action_pins_permissions_step_and_job_deadlines':True,'unique_product_method_ids':116,
        'groups':[15,51,50],'unit_names':39,'original_two_independent_180_plus3_owners_unchanged':True,
        'compiler_20wall_10cpu_1MiB_unchanged':True,'metadata_128KiB_raw_192KiB_stdout_unchanged':True,
        'candidate_946_unchanged':True,'expected_test_bytes_unchanged':True}
(root/'SOURCE-CONTROLS.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,sort_keys=True))
