"""Static byte-capacity planning; no owner or product is executed."""
from pathlib import Path
import ast
import json
import hashlib
import sys

root = Path(sys.argv[1])
source = Path(sys.argv[2])
policy = json.loads((root / 'policy.json').read_bytes())
snapshot = json.loads((source.parent / 'source-control-r3/child/source-after.json').read_bytes())
plan = json.loads((source.parent / 'PURE-TREE-PLAN.json').read_bytes())
tree = ast.parse((source / 'tools/hia_selfhost_contract.py').read_bytes())
assign = [n for n in tree.body if isinstance(n, ast.Assign) and
          any(isinstance(t, ast.Name) and t.id == 'SOURCE_FILES' for t in n.targets)]
assert len(assign) == 1
names = set(ast.literal_eval(assign[0].value))
names.update(r['path'] for r in plan['leaves'] if r['path'].startswith('hepta/') and r['path'].endswith('.py'))
names.add('docs/HIA_SELFHOST_CORE_SUPPORT.json')
assert len(names) == 828 and names <= set(snapshot)
prefix = '/home/runner/work/Hepta/Hepta/'
src = prefix + 'source/'
op = '/home/runner/work/_temp/hia-core-unpack-native-development-r1/'
control = prefix + 'control/' + policy['control_prefix'] + '/'
sha = '1' * 64
base = {src + name: snapshot[name]['sha256'] for name in names}
for directory in (control, op + 'control/'):
    for name in [*policy['controls'], 'policy.json']:
        base[directory + name] = sha
for name in ('context.json', 'initial-source.json'):
    base[op + name] = sha
# These are explicitly sizing fixtures, not observed runtime identities.
for index in range(50):
    stub = '/planning-system-identity-' + str(index).zfill(2) + '-'
    base[stub + 'x' * (256 - len(stub))] = sha
preparation = {}
for name in ('PREPARATION-ACCEPTANCE.json', 'preparation-setup.json',
             'preparation-guard/request.json', 'preparation-guard/guardian.json',
             'preparation-guard/child.stdout.log', 'preparation-guard/child.stderr.log',
             'preparation/report.json', 'preparation/source-before.json',
             'preparation/derived-source.json', 'preparation/source-after.json',
             'preparation/hia_core_lowering_abi.json'):
    preparation[op + name] = sha
suffixes = ('.receipt.json', '.stdout.log', '.stderr.log', '.request.json', '.input.bin', '.output.bin')
for name in ('B1', 'B2'):
    for suffix in suffixes:
        preparation[op + 'preparation/bootstrap/' + name + suffix] = sha
for name in policy['unit_names']:
    directory = op + 'preparation/bundle/' + name + '/'
    for suffix in suffixes:
        preparation[directory + name + suffix] = sha
    preparation[directory + 'manifest.json'] = sha
    preparation[directory + name + '.image.bin'] = sha
for name in ('manifest.json', 'build.json'):
    preparation[op + 'preparation/bundle/' + name] = sha
    preparation[op + 'preparation/unpack/' + name] = sha
for suffix in suffixes:
    preparation[op + 'preparation/unpack/core-unpack' + suffix] = sha
preparation[op + 'preparation/unpack/core-unpack.image.bin'] = sha
for name in ('B0.so', 'B0.receipt.json', 'B1.image.bin', 'B2.image.bin'):
    preparation[op + 'preparation/bootstrap/' + name] = sha
for name in ('HIA_SELFHOST_LANGUAGE_COVERAGE.json', 'HIA_SELFHOST_CORE_SUPPORT.json'):
    preparation[op + 'preparation/derived/' + name] = sha
    preparation[op + 'preparation/final-' + name] = sha
components = {}
for name in ('COMPONENT-ACCEPTANCE.json', 'components-setup.json',
             'components-guard/request.json', 'components-guard/guardian.json',
             'components-guard/child.stdout.log', 'components-guard/child.stderr.log',
             'components/report.json', 'components/ordinary.unittest.log'):
    components[op + name] = sha
for group in ('shim', 'finite-native'):
    for name in ('report.json', 'unittest.log'):
        components[op + 'components/' + group + '/' + name] = sha
    for stream in ('stdout', 'stderr'):
        components[op + 'components/' + group + '.' + stream + '.log'] = sha
sizes = []
for phase, extra in [('preparation', {}), ('components', preparation),
                     ('tests', {**preparation, **components})]:
    # A conservative command argv reserve exceeds all frozen actual commands.
    request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
               'command': ['x' * 2048], 'cwd': op[:-1],
               'source_identities': {**base, **extra}}
    raw = (json.dumps(request, indent=2, sort_keys=True) + '\n').encode()
    assert len(raw) <= 262144
    sizes.append({'phase': phase, 'source_identities': len(request['source_identities']),
                  'request_bytes_in_planning_fixture': len(raw),
                  'remaining_to_runtime_capacity': 262144 - len(raw)})
report = {'schema': 'hia.core-unpack-native-request-capacity-planning.v1',
          'status': 'STATIC_CAPACITY_FIXTURE_PASS',
          'candidate': policy['candidate'], 'declared_source_inputs': 828,
          'runtime_original_request_capacity': 262144,
          'planning_runtime_identities': 50, 'each_planning_runtime_path_bytes': 256,
          'command_payload_reserve_bytes': 2048,
          'preparation_extra_paths': len(preparation),
          'component_extra_paths': len(components), 'phases': sizes,
          'actual_runtime_request_still_measured_and_refused_if_over_capacity': True,
          'arbitrary_future_path_length_guaranteed': False,
          'owner_or_native_or_product_executed': False,
          'source_hashes_are_actual': True,
          'system_paths_are_planning_placeholders_not_runtime_evidence': True}
target = root / 'REQUEST-CAPACITY-ANALYSIS.json'
with target.open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(report, sort_keys=True))
