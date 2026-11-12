"""AST/byte-only delta audit. Does not import or execute HIA product code."""
from pathlib import Path
import ast
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
checks = []

def require(condition, name):
    if not condition:
        raise AssertionError(name)
    checks.append(name)

def pin(path, raw):
    return {'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def assignment(tree, name):
    matches = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    require(len(matches) == 1, 'unique assignment: ' + name)
    return ast.literal_eval(matches[0])

def funcs(tree):
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}

def dump(node):
    return ast.dump(node, include_attributes=False)

generator = 'tools/generate_hia_json_wire.py'
old_gen = (ROOT / 'baseline' / generator).read_text()
new_gen = (ROOT / 'inputs' / generator).read_text()
old_tree, new_tree = ast.parse(old_gen), ast.parse(new_gen)
old_hia = assignment(old_tree, 'SOURCE') + assignment(old_tree, 'ENCODER')
new_hia = assignment(new_tree, 'SOURCE') + assignment(new_tree, 'ENCODER')
old_functions, new_functions = funcs(ast.parse(old_hia)), funcs(ast.parse(new_hia))
added = {'key_summary', 'key_fact', 'key_norm_begin'}
require(set(new_functions) - set(old_functions) == added, 'exactly three new HIA helpers')
require(set(old_functions) <= set(new_functions), 'no HIA helper removed')
changed = {'json_wire', 'preflight', 'encode'}
for name in sorted(set(old_functions) - changed):
    require(ast.get_source_segment(old_hia, old_functions[name]) ==
            ast.get_source_segment(new_hia, new_functions[name]), 'unchanged full HIA body: ' + name)

class ReverseCalls(ast.NodeTransformer):
    def visit_Call(self, node):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name):
            if node.func.id == 'key_summary':
                require(len(node.args) == 3 and not node.keywords, 'key_summary signature')
                node = ast.Call(ast.Name('ask', ast.Load()), [node.args[0], ast.Constant(1),
                    node.args[1], ast.Constant(0), ast.Constant(0), ast.Constant(0), node.args[2]], [])
            elif node.func.id == 'key_fact':
                require(len(node.args) == 3 and isinstance(node.args[2], ast.Constant)
                        and node.args[2].value in (24, 32, 40, 48), 'fixed key fact offset')
                node = ast.Call(ast.Name('read64', ast.Load()), [node.args[0], node.args[2]], [])
            elif node.func.id == 'key_norm_begin':
                node.func.id = 'norm_begin'
        return node

for name in ('preflight', 'encode'):
    projected = ReverseCalls().visit(new_functions[name])
    require(dump(projected) == dump(old_functions[name]), 'exact key-only reverse projection: ' + name)

class RemoveVersionFour(ast.NodeTransformer):
    def visit_BoolOp(self, node):
        node = self.generic_visit(node)
        remaining = []
        for child in node.values:
            is_four = (isinstance(child, ast.Compare) and len(child.comparators) == 1
                       and isinstance(child.comparators[0], ast.Name)
                       and child.comparators[0].id == 'KEY_SUMMARY_MAGIC')
            if is_four:
                require((isinstance(node.op, ast.Or) and isinstance(child.ops[0], ast.Eq))
                        or (isinstance(node.op, ast.And) and isinstance(child.ops[0], ast.NotEq)),
                        'only additive version-four admission comparisons')
            else:
                remaining.append(child)
        require(bool(remaining), 'version projection keeps original condition')
        return remaining[0] if len(remaining) == 1 else ast.BoolOp(node.op, remaining)

require(dump(RemoveVersionFour().visit(new_functions['json_wire'])) == dump(old_functions['json_wire']),
        'complete main HIA body reverse projection')
for name in ('source_program', 'document'):
    require(ast.get_source_segment(old_gen, funcs(old_tree)[name]) ==
            ast.get_source_segment(new_gen, funcs(new_tree)[name]), 'unchanged authoring pipeline: ' + name)

bridge = 'hepta/hia_json_wire_native.py'
old_raw, new_raw = (ROOT / 'baseline' / bridge).read_text(), (ROOT / 'inputs' / bridge).read_text()
old_nodes, new_nodes = funcs(ast.parse(old_raw)), funcs(ast.parse(new_raw))
require(set(old_nodes) == set(new_nodes), 'bridge class/function names preserved')
for name in sorted(set(old_nodes) - {'WireSession', 'NativeJsonWire'}):
    require(ast.get_source_segment(old_raw, old_nodes[name]) ==
            ast.get_source_segment(new_raw, new_nodes[name]), 'unchanged bridge owner: ' + name)
for cls, allowed in (('WireSession', {'__init__'}), ('NativeJsonWire', {'encode_ordinary'})):
    before, after = funcs(old_nodes[cls]), funcs(new_nodes[cls])
    require(set(before) == set(after), 'bridge method names preserved: ' + cls)
    for name in set(before) - allowed:
        require(ast.get_source_segment(old_raw, before[name]) == ast.get_source_segment(new_raw, after[name]),
                'unchanged bridge method: ' + cls + '.' + name)
cache = 'tests/test_hia_json_wire_cache.py'
old_cache, new_cache = (ROOT / 'baseline' / cache).read_bytes(), (ROOT / 'inputs' / cache).read_bytes()
require(new_cache.replace(b'self.assertEqual(seen, [(True, native.KEY_SUMMARY_MAGIC)])',
                         b'self.assertEqual(seen, [(True, native.CACHED_MAGIC)])') == old_cache,
        'seven old cache methods unchanged except strict ordinary version assertion')

new_test_path = 'tests/test_hia_json_wire_key_summary.py'
new_tests = ast.parse((ROOT / 'inputs' / new_test_path).read_text())
ids = {}
for node in new_tests.body:
    if isinstance(node, ast.ClassDef) and node.name.endswith('Tests'):
        methods = [child.name for child in node.body if isinstance(child, ast.FunctionDef)
                   and child.name.startswith('test_')]
        require(len(methods) == 6 and len(set(methods)) == 6, 'six exact controls: ' + node.name)
        ids[node.name] = ['tests.test_hia_json_wire_key_summary.' + node.name + '.' + method
                          for method in sorted(methods)]
protected = [
    'hepta/hia_agent_service.py', 'hepta/hia_agent_runner.py',
    'hepta/hia_json_preflight_native.py', 'hepta/hia_program_tools.py',
    'tools/qualify_hia_json_wire_native_callers.py',
    'tests/test_hia_agent_native_tools.py', 'tests/test_hia_json_wire_native.py',
    'tests/test_hia_json_wire_entry.py', 'examples/hia_bootstrap/json_wire.hiaasm',
]
pins = [pin(name, (BASE / name).read_bytes()) for name in protected]
require(not any((ROOT / 'inputs' / name).exists() for name in protected),
        'no observer admission, original caller, workload, assertion, or old HIA asset overwritten')
test_source = (BASE / 'tests/test_hia_agent_native_tools.py').read_text()
test_class = next(node for node in ast.parse(test_source).body
                  if isinstance(node, ast.ClassDef) and node.name == 'NativeLifecycleTests')
method = next(node for node in test_class.body if isinstance(node, ast.FunctionDef)
              and node.name == 'test_native_timeout_is_incomplete_terminated_and_not_adoptable')
method_raw = ast.get_source_segment(test_source, method).encode()
report = {'schema': 'hepta.hia.json-wire-key-summary.static-audit.v1',
          'status': 'AST_AND_BYTE_PROJECTION_PASS_ONLY', 'checks': checks,
          'source_controls': ids['WireKeySummarySourceTests'],
          'native_controls': ids['WireKeySummaryNativeTests'],
          'protected_input_pins': pins, 'original_five_second_method': pin(method.name, method_raw),
          'generation_executed': False, 'source_or_core_vm_controls_executed': False,
          'native_executed': False, 'performance_measured': False,
          'old_89_or_7_cache_ids_removed': False,
          'candidate_files': [pin(str(path.relative_to(ROOT)), path.read_bytes())
                              for path in sorted((ROOT / 'inputs').rglob('*')) if path.is_file()]}
path = ROOT / (sys.argv[1] if len(sys.argv) == 2 else 'STATIC-AUDIT-final.json')
if path.exists():
    raise AssertionError('static report already exists')
path.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'checks': len(checks),
                  'source_controls': len(report['source_controls']),
                  'native_controls': len(report['native_controls'])}))
