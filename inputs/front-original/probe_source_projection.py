"""Explicit projection of the frozen R5 transport and complete original policy ASTs."""
from pathlib import Path
from hashlib import sha256
import argparse
import ast
import copy
import json

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
root = args.source.resolve(strict=True)
args.output.mkdir(exist_ok=False)
original_raw = (root / 'tests/fixtures/hia_front_continuation_r5.py.txt').read_bytes()
assert sha256(original_raw).hexdigest() == 'd896b591af434a46c1cf3835fe851a70b59e3225cd7bbcbdecf57eb6cab601b5'
current_raw = (root / 'hepta/hia_front_continuation.py').read_bytes()
original, current = ast.parse(original_raw), ast.parse(current_raw)
def inventory(tree):
    result = {}
    for item in tree.body:
        if isinstance(item, (ast.FunctionDef, ast.ClassDef)):
            result[item.name] = item
    return result
old, new = inventory(original), inventory(current)
def rendered(node):
    return ast.dump(node, include_attributes=False)
fixed_functions = ('_read_word', '_capture', '_capture_with_handler', '_runtime_profile')
for name in fixed_functions:
    assert rendered(old[name]) == rendered(new[name]), name
fixed = {
    ('PlanFrame', 'ContinuationFrame'): ('__init__', '_get', '_set', '_clear', 'close',
        '_retire', '__del__', '_invoke', 'step', '_accept_result', 'service', '_parts',
        '_move_call_operand', '_effect', 'drive', 'take'),
    ('NativeMachinePlanControl', 'NativeContinuationImage'):
        ('__init__', '_initialize_control', 'function', 'literal'),
}
projected = []
for (a, b), methods in fixed.items():
    old_methods = {item.name: item for item in old[a].body if isinstance(item, ast.FunctionDef)}
    new_methods = {item.name: item for item in new[b].body if isinstance(item, ast.FunctionDef)}
    for name in methods:
        left, right = copy.deepcopy(old_methods[name]), copy.deepcopy(new_methods[name])
        if name == '_effect':
            for node, expected in ((left, 'old'), (right, 'new')):
                found = [item for item in ast.walk(node) if isinstance(item, ast.If)
                    and rendered(item.test) == rendered(ast.parse('op == 19', mode='eval').body)]
                assert len(found) == 1
                body = found[0].body
                if expected == 'old':
                    assert len(body) == 2 and isinstance(body[0], ast.ImportFrom)
                    assert body[0].level == 1 and body[0].module is None
                    assert [alias.name for alias in body[0].names] == ['hia_program']
                else:
                    assert rendered(body[0]) == rendered(ast.parse(
                        "raise NotImplementedError('public-front owner must supply its fixed import primitive')").body[0])
                    assert len(body) == 1
                found[0].body = [ast.Pass()]
        if name == '_initialize_control':
            for node, expected in ((left, 7), (right, 1)):
                found = [item for item in ast.walk(node) if isinstance(item, ast.Compare)
                    and isinstance(item.left, ast.Name) and item.left.id == 'functions'
                    and len(item.ops) == 1 and isinstance(item.ops[0], ast.Lt)]
                assert len(found) == 1 and len(found[0].comparators) == 1
                assert isinstance(found[0].comparators[0], ast.Constant)
                assert found[0].comparators[0].value == expected
                found[0].comparators[0] = ast.Constant(1)
        assert rendered(left) == rendered(right), (a, b, name)
        projected.append(b + '.' + name)
policies = []
for source_name, policy_name in (
        ('hia_program.py', 'hia_core_verification_policy.py'),
        ('hia_agent_assembly.py', 'hia_assembly_front_policy.py')):
    source_tree = ast.parse((root / 'hepta' / source_name).read_bytes())
    original_nodes = {}
    for node in source_tree.body:
        if isinstance(node, ast.FunctionDef) and node.name not in original_nodes:
            original_nodes[node.name] = node
    policy_nodes = [node for node in ast.parse((root / 'tools' / policy_name).read_bytes()).body
                    if isinstance(node, ast.FunctionDef)]
    assert len(policy_nodes) == (2 if source_name == 'hia_program.py' else 12)
    for node in policy_nodes:
        assert rendered(node) == rendered(original_nodes[node.name]), node.name
    policies.append({'module': source_name, 'names': [node.name for node in policy_nodes]})
modules = ('hia_front_continuation', 'hia_front_runtime', 'hia_front_selection',
           'hia_core_verification_native', 'hia_core_verification_ports', 'hia_core_verification_selection')
for module in modules:
    tree = ast.parse((root / 'hepta' / (module + '.py')).read_bytes())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ('eval', 'exec', 'compile', '__import__'), module
        if isinstance(node, ast.ImportFrom):
            imported = [node.module or ''] + [item.name for item in node.names]
            assert not any('hia_agent_assembly' in name or 'hia_program_tools' in name
                or 'hia_program_native' in name or 'hia_machine_plan_control_native' in name
                for name in imported), (module, imported)
report = {'schema': 'hia.front.pure-continuation-source-projection.v81.r3',
    'status': 'PASS', 'fixed_functions': list(fixed_functions), 'fixed_methods': projected,
    'complete_original_policy_asts': policies, 'core_modules': list(modules),
    'projections': ['fixed owner import port', 'generic nonempty table; concrete exact2/16 admission retained'],
    'original_r5_sha256': sha256(original_raw).hexdigest(),
    'current_transport_sha256': sha256(current_raw).hexdigest(),
    'scope': 'SOURCE_ONLY; runtime gates recorded independently'}
(args.output / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': 'PASS', 'fixed_methods': len(projected), 'fixed_functions': len(fixed_functions),
                  'original_policy_functions': sum(len(row['names']) for row in policies)}))
