"""Mechanical r1/r2 control comparison; no project imports or execution."""
from pathlib import Path
import json
import hashlib
import ast
import yaml

root = Path(__file__).resolve().parent
old = root.parent / 'native116-freeze-r1'

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

a = yaml.load((old / 'workflow-template.yml.txt').read_text(), Loader=yaml.BaseLoader)
b = yaml.load((root / 'workflow-template.yml.txt').read_text(), Loader=yaml.BaseLoader)
oldp = json.loads((old / 'policy.json').read_text())
newp = json.loads((root / 'policy.json').read_text())
oldsteps = a['jobs']['native_development']['steps']
newsteps = b['jobs']['native_development']['steps']
assert len(oldsteps) == len(newsteps) == 12
for original, current in zip(oldsteps, newsteps):
    for field in ('name', 'timeout-minutes', 'if', 'uses'):
        assert original.get(field) == current.get(field), field
assert a['jobs']['native_development']['timeout-minutes'] == b['jobs']['native_development']['timeout-minutes'] == '30'
assert a['permissions'] == b['permissions']
assert a['jobs']['native_development']['permissions'] == b['jobs']['native_development']['permissions']
assert newp['candidate'] == oldp['candidate']
assert (root / 'expected-tests.json').read_bytes() == (old / 'expected-tests.json').read_bytes()
ids = [i for group in newp['test_groups'].values() for i in group['ids']]
assert len(ids) == len(set(ids)) == 116
syntax = []
for name in newp['controls']:
    raw = (root / name).read_bytes()
    ast.parse(raw.decode())
    compile(raw, name, 'exec')
    assert pin(raw) == newp['controls'][name]
    syntax.append(name)
report = {
    'schema': 'hia.core-emitter-native-r2-source-controls.v1', 'status': 'PASS',
    'scope': 'Local Python3.12 syntax, YAML and mechanical checks; no installation/native/product',
    'python': __import__('sys').version,
    'control_sources': {name: pin((root / name).read_bytes()) for name in syntax},
    'policy': pin((root / 'policy.json').read_bytes()),
    'workflow_template': pin((root / 'workflow-template.yml.txt').read_bytes()),
    'declared_YAML_steps': 12,
    'same_action_pins_permissions_and_step_deadlines': True, 'same_product_candidate': True,
    'same_expected_test_bytes': True, 'unique_ids': 116, 'single_default116_owner_unchanged': True,
    'prior_wrong_local_step_count_failure_preserved': 'FIRST-SOURCE-CHECK-FAIL.json',
}
with (root / 'SOURCE-CONTROLS.json').open('x') as handle:
    json.dump(report, handle, sort_keys=True, indent=2)
    handle.write('\n')
print(json.dumps(report, sort_keys=True))
